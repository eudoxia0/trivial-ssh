(in-package :libssh2)

(defmacro result-or-error (&body body)
  `(let ((results (multiple-value-list (progn ,@body)))
         (throwable-errors *errors-list*))
     (if (find (car results)
               throwable-errors)
         (error 'libssh2-invalid-error-code :code (car results))
         (values-list results))))

(defun print-memory (addr size)
  (format t "~{~x ~}"
          (loop for i below size
             collect (mem-aref addr :unsigned-char i))))

(define-foreign-library libssh2
  (:darwin "libssh2.dylib")
  (:unix  "libssh2.so.1")
  (:win32 "libssh2-1.dll")
  (t (:default "libssh2")))

(use-foreign-library libssh2)

(defcfun ("libssh2_init" %library-init) +ERROR-CODE+)
(defun library-init ()
  (result-or-error
    (%library-init)))

(defcfun ("libssh2_version" %library-version) :string
  (required :int))

(defcfun ("libssh2_exit" library-exit) :void)

(defcfun ("libssh2_session_init_ex" session-init-ex) +session+
  (alloc :pointer) (free :pointer) (realloc :pointer) (abstract :pointer))
(defcfun ("libssh2_session_free" %session-free) +ERROR-CODE+
  (session +session+))
(defun session-free (session)
  (%session-free session))

(defcfun ("libssh2_session_last_error" %session-last-error) +ERROR-CODE+
  (session +session+)
  (error-message :pointer) (error-message-buffer-size :pointer)
  (ownership :int))

(defun session-last-error (session)
  (with-foreign-objects ((fo-error-message-buffer-ptr   :pointer 1)
                         (fo-error-message-buffer-size  :int     1))
    (let ((retval (%session-last-error session
                                       fo-error-message-buffer-ptr
                                       fo-error-message-buffer-size
                                       0)))
      (let ((error-message-ptr  (mem-aref fo-error-message-buffer-ptr :pointer 0)))
        (values-list (list (convert-from-foreign error-message-ptr :string)
                           retval))))))


(defcfun ("libssh2_session_last_errno" session-last-errno) +ERROR-CODE+
  (session +session+))

(defcfun ("libssh2_trace" library-trace) :void
  (session +session+) (options +TRACE-OPTIONS+))

(defcfun ("libssh2_session_set_blocking" session-set-blocking) :void
  (session +session+) (blocking +BLOCKING+))

(defun session-init ()
  (let ((session (session-init-ex (null-pointer)
                                  (null-pointer)
                                  (null-pointer)
                                  (null-pointer))))
    (if (null-pointer-p session)
        (result-or-error :UNKNOWN)
        (progn
          (session-set-blocking session :NON-BLOCKING)
          session))))

(defcfun ("libssh2_session_disconnect_ex" %session-disconnect) +ERROR-CODE+
  (session +session+) (reason +DISCONNECT-CODE+) (description :string) (lang :string))

(defun session-disconnect (session &key
                           (reason :AUTH-CANCELLED-BY-USER)
                           (description "")
                           (lang ""))
  (with-foreign-strings ((fs-description description)
                         (fs-lang        lang))
    (result-or-error
      (%session-disconnect session reason fs-description fs-lang))))

(defmacro with-session ( (session) &body body )
  `(let ((,session (session-init)))
     (unwind-protect
          (progn
            ,@body)
       (session-free ,session))))

(if (foreign-symbol-pointer "libssh2_session_handshake")
    (defcfun ("libssh2_session_handshake" %session-handshake) +ERROR-CODE+
      (session +session+) (socket :int))
    (defcfun ("libssh2_session_startup" %session-handshake) +ERROR-CODE+
      (session +session+) (socket :int)))

(defun session-handshake (session socket)
  (result-or-error
    (%session-handshake session socket)))

(defcfun ("libssh2_userauth_list" %session-auth-methods-list) :string
  (session +session+) (username :string) (username-length :unsigned-int))

(defun session-auth-methods-list (session username)
  (with-foreign-string ((fs-username fs-username-size) username)
    (let ((result  (%session-auth-methods-list
                    session fs-username (- fs-username-size 1))))
      (if result
          (mapcar (lambda (item) (intern (string-upcase item) 'keyword))
                  (split-sequence:split-sequence
                   #\, result))
          (result-or-error
            (session-last-errno session))))))

(defcfun ("libssh2_agent_init" %agent-init) +ssh-agent+
  (session +session+))

(defmacro with-agent ((agent session) &body body)
  `(let ((,agent (agent-init ,session)))
     (unwind-protect
          (progn ,@body)
       (unless (null-pointer-p ,agent)
         (agent-free ,agent)))))

(defun agent-init (session)
  (let ((agent (%agent-init session)))
    (if (null-pointer-p agent)
        (result-or-error
          (session-last-errno session))
        agent)))

(defcfun ("libssh2_agent_free" agent-free) :void
  (agent +ssh-agent+))

(defcfun ("libssh2_agent_connect" %agent-connect) +ERROR-CODE+
  (agent +ssh-agent+))
(defun agent-connect (agent)
  (result-or-error
    (%agent-connect agent)))

(defcfun ("libssh2_agent_disconnect" %agent-disconnect) +ERROR-CODE+
  (agent +ssh-agent+))
(defun agent-disconnect (agent)
  (result-or-error
    (%agent-disconnect agent)))

(defcfun ("libssh2_agent_list_identities" %agent-list-identies) +ERROR-CODE+
  (agent +ssh-agent+))
(defun agent-list-identies (agent)
  (result-or-error
    (%agent-list-identies agent)))

(defcfun ("libssh2_agent_get_identity" %agent-get-identity) +IDENTITY-AMOUNT+
  (agent +ssh-agent+)
  (store :pointer) (previous-public-key :pointer))

(defun agent-identities-iterator (agent)
  (when (eq  (agent-list-identies agent) :ERROR-NONE)
    (let ((agent agent)
          (prev  (null-pointer)))
      (lambda ()
        (with-foreign-object (store :pointer)
          (unless (eq (%agent-get-identity agent store prev)
                      :END)
            (setf prev
                  (mem-aref store :pointer 0))))))))

(defmacro foreach-agent-identity ((identy agent) &body body)
  `(let ((agent ,agent)
         (list-identies (agent-list-indenties ,agent))
         (prev (null-pointer)))
     (if (eq list-identies :ERROR-NONE)
         (with-foreign-object (store :pointer)
           (labels
               ((process-next-identity ()
                  (unless (eq (--agent-get-identity agent store prev)
                              :END)
                    (let ((,identy (setf prev
                                         (mem-aref store :pointer 0))))
                      ,@body
                      (process-next-identity)))))
             (process-next-identity))))))

(defcfun ("libssh2_knownhost_init" %known-hosts-init) +known-hosts+
  (session +session+))
(defun known-hosts-init (session)
  (let ((known-hosts (%known-hosts-init session)))
    (if (null-pointer-p known-hosts)
        (result-or-error
          (session-last-errno session))
        known-hosts)))

(defcfun ("libssh2_knownhost_free" known-hosts-free) :void
  (known-hosts +known-hosts+))

(defcfun ("libssh2_knownhost_readfile" %known-hosts-readfile) :int
  (known-hosts +known-hosts+) (filename :string) (type :int))

(defcfun ("libssh2_knownhost_writefile" %known-hosts-writefile) :int
  (known-hosts +known-hosts+) (filename :string) (type :int))

(defun known-hosts-readfile (hosts file)
  (with-foreign-string (foreign-file file)
    (let ((ret (%known-hosts-readfile hosts foreign-file 1)))
      (if (>= ret 0)
          (convert-from-foreign 0 '+ERROR-CODE+)
          (result-or-error
           (convert-from-foreign ret '+ERROR-CODE+))))))

(defun known-hosts-writefile (hosts file)
  (with-foreign-string (foreign-file file)
    (let ((ret (%known-hosts-writefile hosts foreign-file 1)))
      (if (>= ret 0)
          (convert-from-foreign 0 '+ERROR-CODE+)
          (result-or-error
            (convert-from-foreign ret '+ERROR-CODE+))))))

(defcfun ("libssh2_session_hostkey" %session-hostkey)  +key+
  (session +session+) (len :pointer) (type :pointer))

(defun session-hostkey (session)
  (with-foreign-objects ((len :unsigned-int 1)
                        (type :int 1))
    (let ((result (%session-hostkey session len type)))
      (make-key :data result
                :size (mem-aref len :long 0)
                :type (mem-aref type :int 0)))))

(defcfun ("libssh2_hostkey_hash" session-hostkey-hash) +keyhash+
  (session +session+) (hash-type +HASH-TYPE+))

(defun session-hostkey-fingerprint (session &optional (type :SHA1))
  (let ((hash (session-hostkey-hash session type)))
    (format nil "~{~2,'0X~^:~}"
            (loop for i below (if (eq type :SHA1) 20 16)
               collect (mem-aref hash :unsigned-char i)))))

(defcfun ("libssh2_knownhost_checkp" %known-hosts-checkp) +CHECK-VERDICT+
  (known-hosts +known-hosts+) (hostname :string) (port :int)
  (key +key+) (key-data-size :unsigned-int)
  (type :int)  (known-host :pointer))

(defcfun ("libssh2_knownhost_check" %known-hosts-check) +CHECK-VERDICT+
  (known-hosts +known-hosts+) (hostname :string)
  (key +key+) (key-data-size :unsigned-int)
  (type :int)  (known-host :pointer))

(defun known-hosts-check (known-hosts hostname key
                          &key
                            (port nil)
                            (flags '(.type-plain. .raw.))
                            (known-host (null-pointer)))
  (let ((fp (key-data key)))
    (if (null-pointer-p fp)
        (result-or-error :UNKNOWN)
        (with-foreign-string (fs-hostname hostname)
          (with-foreign-object (hostinfo :pointer 1)
            (setf (mem-aref hostinfo :pointer 0) known-host)
            (if port
                (%known-hosts-checkp known-hosts fs-hostname port
                                     fp
                                     (key-size key)
                                     (foreign-bitfield-value '+known-hosts-flags+ flags)
                                     hostinfo)
                (%known-hosts-check known-hosts fs-hostname
                                    fp
                                    (key-size key)
                                    (foreign-bitfield-value '+known-hosts-flags+ flags)
                                    hostinfo)))))))

(define-condition known-hosts-reading-error (ssh-generic-error)
  ((file :type     string
         :initarg  :file
         :accessor file)))

(defmethod print-object :after ((khre known-hosts-reading-error) stream)
  (format stream "// ~a" (file khre)))

(defmacro with-known-hosts ( ( known-hosts (session known-hosts-filename)) &body body )
  `(let ((,known-hosts (known-hosts-init ,session))
         (*errors-list* (remove :ERROR-FILE *default-errors-list*)))
     (unwind-protect
          (if (and (not (null-pointer-p ,known-hosts))
                   (eq (labels
                           ((try-again ()
                              (let ((result (known-hosts-readfile ,known-hosts ,known-hosts-filename)))
                                (if (eq result :ERROR-FILE)
                                    (restart-case
                                        (with-last-error (,session known-hosts-reading-error)
                                          :file ,known-hosts-filename)
                                      (try-create-file ()
                                        (unless
                                            (eq (known-hosts-writefile ,known-hosts ,known-hosts-filename)
                                                :ERROR-NONE)
                                          (with-last-error (,session known-hosts-reading-error)
                                            :file ,known-hosts-filename))
                                        (try-again))
                                      (ignore () nil))
                                    result))))
                         (try-again)) :ERROR-NONE))
              (progn
                ,@body)
              (with-last-error (,session known-hosts-reading-error)
                :file ,known-hosts-filename))
       (unless (null-pointer-p ,known-hosts)
         (known-hosts-free ,known-hosts)))))

(defcfun ("libssh2_knownhost_addc" %known-hosts-addc) +ERROR-CODE+
  (known-hosts +known-hosts+)
  (host :string) (salt :string) (key :pointer) (key-length :unsigned-int)
  (comment :string) (comment-length :unsigned-int)
  (typemask :int) (known-host +known-host+))

(defun known-hosts-add (known-hosts host-full-string key
                        &key
                          (comment "")
                          (flags '(.type-plain. .raw. .ssh.))
                          (salt  "")
                          (store (null-pointer)))
  (if (and (not (null-pointer-p known-hosts))
           (not (null-pointer-p (key-data key)))
           (stringp host-full-string))
      (with-foreign-strings ((fs-host-full-string host-full-string)
                             (fs-salt     salt)
                             ((fs-comment fs-comment-size) comment))
        (result-or-error
          (%known-hosts-addc known-hosts
                             fs-host-full-string fs-salt
                             (key-data key) (key-size key)
                             fs-comment (- fs-comment-size 1)
                             (foreign-bitfield-value '+known-hosts-flags+ flags)
                             store)))))

(defcfun ("libssh2_agent_userauth" %agent-userauth) +ERROR-CODE+
  (agent +ssh-agent+) (username :string) (identity :pointer))

(defun user-auth-agent (agent username identity)
  (with-foreign-string (fs-username username)
    (result-or-error
      (%agent-userauth agent fs-username identity))))

(defcfun ("libssh2_userauth_password_ex" %user-auth-password) +ERROR-CODE+
  (session +session+)
  (username :string) (username-length :unsigned-int)
  (password :string) (password-length :unsigned-int)
  (password-change :pointer))

(defun user-auth-password (session username password &optional (callback (null-pointer)))
  (with-foreign-strings (((fs-username fs-username-size) username)
                         ((fs-password fs-password-size) password))
    (result-or-error
      (%user-auth-password session
                           fs-username (- fs-username-size 1)
                           fs-password (- fs-password-size 1)
                           callback))))

(defcfun ("libssh2_userauth_keyboard_interactive_ex" %user-auth-interactive) +ERROR-CODE+
  (session +session+)
  (username :string) (username-length :unsigned-int)
  (callback :pointer))

(defun user-auth-interactive (session username callback)
  (with-foreign-string ((fs-username fs-username-size) username)
    (%user-auth-interactive session
                            fs-username
                            (- fs-username-size 1)
                            callback)))

(defvar *keyboard-interactive-password* "")
(defcallback trivial-keyboard-interactive-emulation :void
    ((login :pointer)      (login-length       :unsigned-int)
     (instruction :string) (instruction-length :unsigned-int)
     (num-prompts :int)
     (prompts   (:pointer +kbd-prompt+))
     (responses (:pointer +kbd-response+))
     (abstract  (:pointer :pointer)))
  ;; Just don't care about input. Only send password
  ;; Please, write you'r own callback, if you care
  (declare
   (ignore login)       (ignore login-length)
   (ignore instruction) (ignore instruction-length)
   (ignore prompts)     (ignore abstract))
  (loop for i below num-prompts
     do
       (with-foreign-slots ((text length)
                            (mem-aref responses '+kbd-response+ i)
                            +kbd-response+)
         (setf text   (foreign-string-alloc *keyboard-interactive-password*))
         (setf length (foreign-funcall "strlen" :pointer text :unsigned-int)))))

(defun user-auth-interactive-trivial (session username password)
  (let ((*keyboard-interactive-password* password))
    (user-auth-interactive session username
                           (callback trivial-keyboard-interactive-emulation))))

(defcfun ("libssh2_userauth_publickey_fromfile_ex" %user-auth-publickey) +ERROR-CODE+
  (session +session+)
  (username :string) (username-len :unsigned-int)
  (public-key :string)
  (private-key :string) (password :string))

(defun user-auth-publickey (session username public-key private-key password)
  (with-foreign-strings (((fs-username fs-username-size) username)
                         (fs-public-key  public-key)
                         (fs-private-key private-key)
                         (fs-password    password))
    (result-or-error
      (%user-auth-publickey session fs-username (- fs-username-size 1)
                            fs-public-key fs-private-key fs-password))))

(defcfun ("libssh2_channel_open_ex" %channel-open-ex) +channel+
  (session +session+) (channel-type :string) (channel-type-length :unsigned-int)
  (window-size :unsigned-int) (packet-size :unsigned-int)
  (message :string) (message-length :unsigned-int))

(defun channel-open (session &key (channel-type "session")
                               (window-size 262144)
                               (packet-size 32768)
                               (message ""))
  (with-foreign-strings (((fs-channel-type fs-channel-type-size) channel-type)
                         ((fs-message      fs-message-size)      message))
    (let* ((pass-message (if (string= message "")
                             (null-pointer)
                             fs-message))
           (pass-message-size (if (string= message "")
                                  0
                                  (- fs-message-size 1)))
           (new-channel
            (%channel-open-ex session
                              fs-channel-type (- fs-channel-type-size 1)
                              window-size packet-size
                              pass-message
                              pass-message-size)))
      (if (null-pointer-p new-channel)
          (result-or-error
           (session-last-errno session))
          new-channel))))

(defcfun ("libssh2_channel_close" %channel-close) +ERROR-CODE+
  (channel +channel+))
(defun channel-close (channel)
  (result-or-error
    (%channel-close channel)))

(defcfun ("libssh2_channel_free" %channel-free) +ERROR-CODE+
  (channel +channel+))
(defun channel-free (channel)
  (result-or-error
    (%channel-free channel)))

(defcfun ("libssh2_channel_wait_closed" %channel-wait-closed) +ERROR-CODE+
  (channel +channel+))
(defun channel-wait-closed (channel)
  (result-or-error
    (%channel-wait-closed channel)))

(defcfun ("libssh2_channel_wait_eof" %channel-wait-eof) +ERROR-CODE+
  (channel +channel+))
(defun channel-wait-eof (channel)
  (result-or-error
    (%channel-wait-eof channel)))

(defcfun ("libssh2_channel_process_startup" %channel-process-startup) +ERROR-CODE+
  (channel +channel+)
  (request :string) (request-length :unsigned-int)
  (message :string) (message-length :unsigned-int))

(defcfun ("libssh2_channel_setenv_ex" %channel-setenv-ex) +ERROR-CODE+
  (channel +channel+)
  (varname :string) (varname-len :int)
  (value :string) (value-len :int))

(defun channel-setenv (channel name value)
  (with-foreign-strings (((fs-name  fs-name-size)  name)
                         ((fs-value fs-value-size) value))
    (result-or-error
      (%channel-setenv-ex channel
                          fs-name  (- fs-name-size 1)
                          fs-value (- fs-value-size 1)))))

(defun channel-process-start (channel request message)
  (with-foreign-strings (((fs-request fs-request-size) request)
                         ((fs-message fs-message-size) message))
    (result-or-error
      (%channel-process-startup channel
                                fs-request (- fs-request-size 1)
                                fs-message (- fs-message-size 1)))))

(defun channel-exec (channel cmd)
  (channel-process-start channel "exec" cmd))

(defun channel-shell (channel cmd)
  (channel-process-start channel "shell" cmd))

(defun channel-subsystem (channel cmd)
  (channel-process-start channel "subsystem" cmd))

(defcfun ("libssh2_channel_read_ex" %channel-read-ex) :int
  (channel +CHANNEL+) (stream +STREAM-ID+)
  (buffer :pointer) (buffer-length :unsigned-int))

(defcfun ("libssh2_channel_flush_ex" %channel-flush-ex) :int
  (channel +CHANNEL+) (stream +STREAM-ID+))

(defun channel-flush (channel)
  (let ((ret (%channel-flush-ex channel :ALL)))
    (if (> ret 0)
        :ERROR-NONE
        (result-or-error
          (convert-from-foreign ret '+ERROR-CODE+)))))

(defvar *channel-read-type* :STDOUT)
(defvar *channel-read-zero-as-eof* nil)
(defun channel-read (channel output-buffer &key (start 0) (end nil) (type *channel-read-type*))
  (with-pointer-to-vector-data (buffer output-buffer)
    (let ((ret (%channel-read-ex channel type
                                 (inc-pointer buffer start)
                                 (if end
                                     (- (min end (length output-buffer))
                                        start)
                                     (- (length output-buffer)
                                        start)))))
      (if (>= ret 0)
          (values
           ret
           (cond
             ((and (= ret 0) *channel-read-zero-as-eof*) t)
             ((= ret 0)      (channel-eofp channel))
             (t nil)))
            (result-or-error
              (convert-from-foreign ret '+ERROR-CODE+))))))

(defcfun ("libssh2_channel_write_ex" %channel-write-ex) :int
  (channel +CHANNEL+) (stream +STREAM-ID+)
  (buffer :pointer) (buffer-length :unsigned-int))

(defmacro channel-write-with-conv (name conv)
  `(defun ,name (channel data &key (start 0) (end nil) (type *channel-read-type*))
     (,conv (buffer data)
            (let ((ret (%channel-write-ex channel type
                                          (inc-pointer buffer start)
                                          (if end
                                              (- (min end (length data))
                                                 start)
                                              (- (length data)
                                                 start)))))
              (if (>= ret 0)
                    ret
                  (result-or-error
                    (convert-from-foreign ret '+ERROR-CODE+)))))))

(channel-write-with-conv channel-write with-pointer-to-vector-data)
(channel-write-with-conv channel-write-string with-foreign-string)

(defcfun ("libssh2_channel_send_eof" %channel-send-eof) +ERROR-CODE+
  (channel +channel+))
(defun channel-send-eof (channel)
  (result-or-error
    (%channel-send-eof channel)))

(defcfun ("libssh2_channel_eof" %channel-eofp) +CHANNEL-EOF+
  (channel +channel+))
(defun channel-eofp (channel)
  (eq (%channel-eofp channel) :EOF))

(defcfun ("libssh2_channel_get_exit_status" channel-exit-status) :int
  (channel +channel+))

;; (defcfun ("libssh2_channel_get_exit_signal" --channel-exit-signal) +ERROR-CODE+
;;  (channel +channel+)

(defcfun ("libssh2_scp_recv" %scp-recv) +channel+
  (session +session+) (path :string) (stat +stat+))

(defun channel-scp-recv (session path)
  (with-foreign-string (fs-path path)
    (with-foreign-object (stat '+stat+ 1)
      (let ((result (%scp-recv session path stat)))
        (if (null-pointer-p result)
            (result-or-error
              (session-last-errno session))
            (progn
              (channel-send-eof result)
              (values result
                      (with-foreign-slots ((mode mtime atime) stat +stat+)
                        (list :mode  mode
                              :mtime mtime
                              :atime atime)))))))))

(defcfun ("libssh2_scp_send_ex" %scp-send-ex) +channel+
  (session +session+) (path :string) (mode :int) (size :unsigned-int)
  (mtime :long) (atime :long))

(defun get-universal-unix-time ()
  (- (get-universal-time)
     (encode-universal-time 0 0 0 1 1 1970 0)))

(defun channel-scp-send (session path size
                         &key mode mtime atime)
  (unless mode  (setq mode #b110100000))
  (unless mtime (setq mtime (get-universal-unix-time)))
  (unless atime (setq atime mtime))
  (with-foreign-string (fs-path path)
    (let ((result (%scp-send-ex session fs-path
                                mode size mtime
                                atime)))
      (if (null-pointer-p result)
          (result-or-error
            (session-last-errno session))
          result))))
