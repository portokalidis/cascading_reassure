
//! Original name
static KNOB<string> original_name(KNOB_MODE_WRITEONCE, "pintool",
    "name", "", "Specify executable's original name. For reporting errors.");

//! Reference Id
static KNOB<string> ref_id(KNOB_MODE_WRITEONCE, "pintool",
    "refid", "", "Specify reference-id. For reporting errors.");

//! Notification messages to stderr
static KNOB<bool> notify_stderr(KNOB_MODE_WRITEONCE, "pintool",
    "notify", "0", "Notification messages are also written to stderr.");

