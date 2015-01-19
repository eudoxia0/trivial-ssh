# trivial-ssh: Simple SSH/SCP library for Common Lisp

# Usage

## Overview

~~~lisp
(ssh:with-connection (conn "example.com" (ssh:pass "username" "password"))
  (ssh:with-command (conn iostream "ls -a")
    ;; Write or read to/from the iostream
    )
  (ssh:download-file #p"/remote/file" #p"/local/file")
  (ssh:upload-file #p"/local/file" #p"/remote-file"))
~~~

# License

Copyright (c) 2014-2015 Fernando Borretti (eudoxiahp@gmail.com)

Licensed under the MIT License.
