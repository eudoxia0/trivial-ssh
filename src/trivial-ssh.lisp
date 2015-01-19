(in-package :cl-user)
(defpackage trivial-ssh
  (:use :cl)
  (:nicknames :ssh)
  (:export :hosts-db
           :*automatically-accept-keys*
           :pass
           :key
           :agent
           :with-connection
           :with-command
           :download-file
           :upload-file))
(in-package :trivial-ssh)

;;; Hosts database

(defun hosts-db (name)
  "Path of the hosts database."
  (merge-pathnames
   (make-pathname :directory (list :relative ".ssh")
                  :name name)
   (user-homedir-pathname)))

(defparameter +default-hosts-db+ (hosts-db "trivial_ssh_hosts"))

;; Ensure hosts database exists
(unless (probe-file +default-hosts-db+)
  (with-open-file (file +default-hosts-db+ :if-does-not-exist :create)))

;;; Key handling

(defparameter *automatically-accept-keys* t
  "Determine whether remote keys are automatically accepted. Defaults to true.")

(defun accept-key (conn)
   (libssh2:with-known-hosts (known-hosts
                              ((libssh2:session conn)
                               (libssh2:hosts-db conn)))
     (if (or *automatically-accept-keys*
             (yes-or-no-p "Accept key for ~A?" (libssh2::ssh-host+port-format conn)))
         (progn
           (libssh2:known-hosts-add known-hosts
                                    (libssh2::ssh-host+port-format conn)
                                    (libssh2:ssh-session-key conn)
                                    :comment "")
           (libssh2:known-hosts-writefile known-hosts
                                          (libssh2::hosts-db conn))))))

;;; Connection

(defun pass (username password)
  "Authenticate using a username and password"
  (libssh2:make-password-auth username password))

(defun key (username private-key-path)
  (libssh2:make-publickey-auth username
                               (namestring
                                (make-pathname
                                 :directory (pathname-directory private-key-path)))
                               (pathname-name private-key-path)))

(defun agent (username)
  (libssh2:make-agent-auth username))

(defmacro with-connection ((conn host auth
                            &optional (hosts-db-path +default-hosts-db+)
                              (port 22))
                           &rest body)
  "Execute `body` within the context of the SSH connection `conn`. `host` is the
  host to connect to, `auth` is an authentication object (For example, generated
  with the `pass` function). `hosts-db` is the file storing the known SSH hosts,
  and defaults to `~/.ssh/known_hosts`."
  `(let* ((ssh-conn
            (libssh2:create-ssh-connection
             ,host :hosts-db (namestring ,hosts-db-path) :port ,port)))
     (handler-case
         (libssh2:ssh-verify-session ssh-conn)
       (libssh2:ssh-bad-hostkey nil (accept-key ssh-conn)))
     (libssh2:destroy-ssh-connection ssh-conn)
     (libssh2:with-ssh-connection ,conn
         (,host
          ,auth
          :hosts-db (namestring ,hosts-db-path) :port ,port)
       ,@body)))

;;; Command execution

(defmacro with-command ((conn iostream command) &rest body)
  `(libssh2:with-execute* (,iostream ,conn ,command)
     ,@body))

;;; SCP file transfers

(defun download-file (conn local remote
                      &key (if-exists :supersede) (if-does-not-exist :create))
  (libssh2:with-scp-input (download-stream conn (namestring remote) stat)
    (with-open-file (file-stream (namestring local)
                                 :direction :output
                                 :if-exists if-exists
                                 :if-does-not-exist if-does-not-exist
                                 :element-type '(unsigned-byte 8))
      (uiop:copy-stream-to-stream download-stream file-stream))))

(defun upload-file (conn local remote)
  (with-open-file (file-stream (namestring local)
                               :direction :input
                               :element-type '(unsigned-byte 8))
    (libssh2:with-scp-output (upload-stream conn
                                            (namestring remote)
                                            (file-length file-stream))
      (uiop:copy-stream-to-stream file-stream upload-stream))))
