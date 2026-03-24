function writeAuditLog(userInput) {
  const query =
    "INSERT INTO audit_logs(message) VALUES ('" + userInput + "')";
  return db.query(query);
}
