# trivial-ssh

[![Build Status](https://travis-ci.org/eudoxia0/trivial-ssh.svg?branch=master)](https://travis-ci.org/eudoxia0/trivial-ssh)

A simple SSH/SCP library for Common Lisp.

# Usage

## Installation

Make sure you have `libssh2` installed on your system. Then simply load it with `(ql:quickload :trivial-ssh)`.

## Overview

~~~lisp
(ssh:with-connection (conn "example.com" (ssh:pass "username" "password"))
  (ssh:with-command (conn iostream "ls -a")
    ;; Write or read to/from the iostream
    )
  (ssh:download-file conn #p"/remote/file" #p"/local/file")
  (ssh:upload-file conn #p"/local/file" #p"/remote-file"))
~~~

# License

Copyright (c) 2014-2015 Fernando Borretti (eudoxiahp@gmail.com)

Licensed under the MIT License.
