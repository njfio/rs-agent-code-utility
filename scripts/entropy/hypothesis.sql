-- tokens per delivered diff line, monthly, against entropy metrics
WITH monthly AS (
  SELECT substr(ended_at, 1, 7) AS m,
         SUM(tokens_out) AS toks,
         SUM(lines_added + lines_removed) AS diff_lines,
         COUNT(*) AS sessions
  FROM tasks GROUP BY 1),
entropy AS (
  SELECT month AS m,
         AVG(loc) AS loc, AVG(dup_pct) AS dup_pct,
         AVG(mean_fan_in) AS fan_in
  FROM snapshots GROUP BY 1)
SELECT monthly.m,
       ROUND(toks * 1.0 / NULLIF(diff_lines, 0), 1) AS tokens_per_diff_line,
       sessions, loc, dup_pct, fan_in
FROM monthly LEFT JOIN entropy USING (m)
ORDER BY monthly.m;
