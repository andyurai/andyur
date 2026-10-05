# Is a port actually held by a LISTENING server?
#
# Sourced by the verify gates and the demos, which all refuse to start when a
# port they need is taken -- because binding a port that is already bound fails
# silently in some servers and, worse, succeeds against SOMEONE ELSE's process in
# others, and a gate that verifies the wrong server is a gate that lies.
#
# The naive test is `lsof -ti tcp:$p`, and it is wrong. `-i tcp:$p` matches ANY
# socket with that port at EITHER end, including a client's outbound connection
# and including one already in CLOSED or TIME_WAIT. So a gate that just finished
# talking to port 8677 leaves a dying client socket behind and the NEXT run
# refuses to start, blaming a server that exited minutes ago. That was observed,
# not theorised: two consecutive runs of ./run.sh authority-e2e, the second
# refusing on a CLOSED socket belonging to the first.
#
# `-sTCP:LISTEN` is the fix -- only a process actually accepting on that port.
# It matters most where the caller goes on to KILL what it finds: killing the
# owner of a stray client socket is killing an unrelated process.
port_listener() {  # port -> pids of anything LISTENING on it, one per line
  lsof -ti "tcp:$1" -sTCP:LISTEN 2>/dev/null
}

port_held() {      # port -> true if something is LISTENING on it
  [ -n "$(port_listener "$1")" ]
}
