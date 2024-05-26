index 71de91d..5967fe2 100644
--- a/src/logging.cc
+++ b/src/logging.cc
@@ -2008,11 +2008,9 @@ int64 LogMessage::num_messages(int severity) {
 // Output the COUNTER value. This is only valid if ostream is a
 // LogStream.
 ostream& operator<<(ostream &os, const PRIVATE_Counter&) {
-#ifdef DISABLE_RTTI
-  LogMessage::LogStream *log = static_cast<LogMessage::LogStream*>(&os);
-#else
-  LogMessage::LogStream *log = dynamic_cast<LogMessage::LogStream*>(&os);
-#endif
+
+LogMessage::LogStream *log = static_cast<LogMessage::LogStream*>(&os);
+
   CHECK(log && log == log->self())
       << "You must not use COUNTER with non-glog ostream";
   os << log->ctr();
