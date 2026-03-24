const AWS_ACCESS_KEY_ID: &str = "AKIA5C38F4W0HTH09SN4";
const AWS_SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn aws_credentials() -> (&'static str, &'static str) {
    (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
}
