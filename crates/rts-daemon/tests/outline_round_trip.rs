//! End-to-end test for `Index.Outline` with PageRank ranking.
//!
//! Seeds a workspace with three Rust files where one file is the "hub"
//! — multiple other files reference its symbols. PageRank should rank
//! the hub highest in the returned outline.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn daemon_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts-daemon"))
}

async fn wait_for_socket(path: &std::path::Path, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("socket {} never appeared", path.display());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn round_trip(
    stream: &mut UnixStream,
    id: &str,
    method: &str,
    params: Value,
) -> anyhow::Result<Value> {
    let req = json!({ "id": id, "method": method, "params": params });
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    let (rd, _wr) = stream.split();
    let mut reader = BufReader::new(rd);
    let n = tokio::time::timeout(Duration::from_secs(8), reader.read_until(b'\n', &mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to {method}"))??;
    anyhow::ensure!(n > 0, "EOF before response to {method}");
    Ok(serde_json::from_slice(&buf)?)
}

async fn wait_for_symbol(
    stream: &mut UnixStream,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut id: u64 = 100;
    loop {
        id += 1;
        let resp = round_trip(
            stream,
            &id.to_string(),
            "Index.FindSymbol",
            json!({ "name": name }),
        )
        .await?;
        if !resp["result"]["matches"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("symbol `{name}` never indexed within {:?}", timeout);
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn outline_ranks_hub_file_highest() -> anyhow::Result<()> {
    let runtime_dir = tempfile::tempdir()?;
    let state_dir = tempfile::tempdir()?;
    let home_dir = tempfile::tempdir()?;
    let workspace = tempfile::tempdir()?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700));

    // `hub.rs` defines two symbols. `caller_a.rs` and `caller_b.rs`
    // reference them. PageRank should put `hub.rs` ahead of the
    // callers.
    std::fs::write(
        workspace.path().join("hub.rs"),
        "pub fn hub_compute(x: u32) -> u32 { x + 1 }\npub fn hub_format(x: u32) -> String { x.to_string() }\n",
    )?;
    std::fs::write(
        workspace.path().join("caller_a.rs"),
        "pub fn caller_a_one() {\n    let _ = hub_compute(1);\n    let _ = hub_format(2);\n}\n",
    )?;
    std::fs::write(
        workspace.path().join("caller_b.rs"),
        "pub fn caller_b_one() {\n    let _ = hub_compute(3);\n}\n",
    )?;

    let socket_path = if cfg!(target_os = "macos") {
        home_dir
            .path()
            .join("Library")
            .join("Caches")
            .join("rts")
            .join("default.sock")
    } else {
        runtime_dir.path().join("rts").join("default.sock")
    };

    let mut cmd = Command::new(daemon_bin());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .env("HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("RTS_IDLE_SHUTDOWN_SECS", "60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let _kill = KillOnDrop(&mut child);

    wait_for_socket(&socket_path, Duration::from_secs(5)).await?;
    let mut stream = UnixStream::connect(&socket_path).await?;

    let mount = round_trip(
        &mut stream,
        "1",
        "Workspace.Mount",
        json!({ "root": workspace.path() }),
    )
    .await?;
    assert!(mount["error"].is_null(), "mount: {mount:?}");

    // Wait for all three files' symbols to land in the index.
    wait_for_symbol(&mut stream, "hub_compute", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "caller_a_one", Duration::from_secs(5)).await?;
    wait_for_symbol(&mut stream, "caller_b_one", Duration::from_secs(5)).await?;

    let outline = round_trip(
        &mut stream,
        "10",
        "Index.Outline",
        json!({ "token_budget": 4096 }),
    )
    .await?;
    assert!(outline["error"].is_null(), "outline failed: {outline:?}");
    let files = outline["result"]["outline_json"]["files"]
        .as_array()
        .expect("outline_json.files array");
    assert!(
        files.len() >= 3,
        "expected at least 3 files in outline; got {files:?}"
    );

    let ranks: Vec<(&str, f64)> = files
        .iter()
        .map(|f| {
            (
                f["path"].as_str().unwrap_or(""),
                f["rank"].as_f64().unwrap_or(0.0),
            )
        })
        .collect();

    // Hub should rank strictly higher than each caller.
    let hub_rank = ranks
        .iter()
        .find(|(p, _)| *p == "hub.rs")
        .map(|(_, r)| *r)
        .expect("hub.rs should appear in outline");
    let caller_a_rank = ranks
        .iter()
        .find(|(p, _)| *p == "caller_a.rs")
        .map(|(_, r)| *r)
        .expect("caller_a.rs should appear in outline");
    let caller_b_rank = ranks
        .iter()
        .find(|(p, _)| *p == "caller_b.rs")
        .map(|(_, r)| *r)
        .expect("caller_b.rs should appear in outline");

    assert!(
        hub_rank > caller_a_rank && hub_rank > caller_b_rank,
        "hub should outrank callers; got hub={hub_rank}, caller_a={caller_a_rank}, caller_b={caller_b_rank}"
    );

    // Sanity: outline_text mentions the hub's defined symbols.
    let text = outline["result"]["outline_text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("hub.rs") && text.contains("hub_compute"),
        "outline_text should list hub.rs + hub_compute; got {text:?}"
    );

    Ok(())
}

struct KillOnDrop<'a>(&'a mut std::process::Child);
impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
