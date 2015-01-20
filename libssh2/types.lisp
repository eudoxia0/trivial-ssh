(in-package :libssh2)

(defcenum +DISCONNECT-CODE+
  (:HOST-NOT-ALLOWED-TO-CONNECT          1)
  (:PROTOCOL-ERROR                       2)
  (:KEY-EXCHANGE-FAILED                  3)
  (:RESERVED                             4)
  (:MAC-ERROR                            5)
  (:COMPRESSION-ERROR                    6)
  (:SERVICE-NOT-AVAILABLE                7)
  (:PROTOCOL-VERSION-NOT-SUPPORTED       8)
  (:HOST-KEY-NOT-VERIFIABLE              9)
  (:CONNECTION-LOST                      10)
  (:BY-APPLICATION                       11)
  (:TOO-MANY-CONNECTIONS                 12)
  (:AUTH-CANCELLED-BY-USER               13)
  (:NO-MORE-AUTH-METHODS-AVAILABLE       14)
  (:ILLEGAL-USER-NAME                    15))

(defcenum +ERROR-CODE+
  (:ERROR-NONE                     0)
  (:ERROR-SOCKET-NONE              -1)
  (:ERROR-BANNER-RECV              -2)
  (:ERROR-BANNER-SEND              -3)
  (:ERROR-INVALID-MAC              -4)
  (:ERROR-KEX-FAILURE              -5)
  (:ERROR-ALLOC                    -6)
  (:ERROR-SOCKET-SEND              -7)
  (:ERROR-KEY-EXCHANGE-FAILURE     -8)
  (:ERROR-TIMEOUT                  -9)
  (:ERROR-HOSTKEY-INIT             -10)
  (:ERROR-HOSTKEY-SIGN             -11)
  (:ERROR-DECRYPT                  -12)
  (:ERROR-SOCKET-DISCONNECT        -13)
  (:ERROR-PROTO                    -14)
  (:ERROR-PASSWORD-EXPIRED         -15)
  (:ERROR-FILE                     -16)
  (:ERROR-METHOD-NONE              -17)
  (:ERROR-AUTHENTICATION-FAILED    -18)
  (:ERROR-PUBLICKEY-UNVERIFIED     -19)
  (:ERROR-CHANNEL-OUTOFORDER       -20)
  (:ERROR-CHANNEL-FAILURE          -21)
  (:ERROR-CHANNEL-REQUEST-DENIED   -22)
  (:ERROR-CHANNEL-UNKNOWN          -23)
  (:ERROR-CHANNEL-WINDOW-EXCEEDED  -24)
  (:ERROR-CHANNEL-PACKET-EXCEEDED  -25)
  (:ERROR-CHANNEL-CLOSED           -26)
  (:ERROR-CHANNEL-EOF-SENT         -27)
  (:ERROR-SCP-PROTOCOL             -28)
  (:ERROR-ZLIB                     -29)
  (:ERROR-SOCKET-TIMEOUT           -30)
  (:ERROR-SFTP-PROTOCOL            -31)
  (:ERROR-REQUEST-DENIED           -32)
  (:ERROR-METHOD-NOT-SUPPORTED     -33)
  (:ERROR-INVAL                    -34)
  (:ERROR-INVALID-POLL-TYPE        -35)
  (:ERROR-PUBLICKEY-PROTOCOL       -36)
  (:ERROR-EAGAIN                   -37)
  (:ERROR-BUFFER-TOO-SMALL         -38)
  (:ERROR-BAD-USE                  -39)
  (:ERROR-COMPRESS                 -40)
  (:ERROR-OUT-OF-BOUNDARY          -41)
  (:ERROR-AGENT-PROTOCOL           -42)
  (:ERROR-SOCKET-RECV              -43)
  (:ERROR-ENCRYPT                  -44)
  (:ERROR-BAD-SOCKET               -45)
  (:ERROR-KNOWN-HOSTS              -46))

(defcenum +DISCONNECT-CODE+
  (:HOST-NOT-ALLOWED-TO-CONNECT         1)
  (:PROTOCOL-ERROR                      2)
  (:KEY-EXCHANGE-FAILED                 3)
  (:RESERVED                            4)
  (:MAC-ERROR                           5)
  (:COMPRESSION-ERROR                   6)
  (:SERVICE-NOT-AVAILABLE               7)
  (:PROTOCOL-VERSION-NOT-SUPPORTED      8)
  (:HOST-KEY-NOT-VERIFIABLE             9)
  (:CONNECTION-LOST                     10)
  (:BY-APPLICATION                      11)
  (:TOO-MANY-CONNECTIONS                12)
  (:AUTH-CANCELLED-BY-USER              13)
  (:NO-MORE-AUTH-METHODS-AVAILABLE      14)
  (:ILLEGAL-USER-NAME                   15))

(defcenum +BLOCKING+
  (:BLOCKING     1)
  (:NON-BLOCKING 0))

(defcenum +IDENTITY-AMOUNT+
  (:MORE 0)
  (:END  1))

(defcenum +CHANNEL-EOF+
  (:NOT-EOF 0)
  (:EOF     1))

(defcenum +STREAM-ID+
  (:STDOUT    0)
  (:STDERR    1)
  (:EXTENDED -1)
  (:ALL      -2))

(defcenum +HASH-TYPE+
  (:MD5  1)
  (:SHA1 2))

(defcenum +CHECK-VERDICT+
  (:FAILURE    3)
  (:NOT-FOUND  2)
  (:MISMATCH   1)
  (:MATCH      0))

(defctype +session+     :pointer)
(defctype +key+         :pointer)
(defctype +ssh-agent+   :pointer)
(defctype +known-hosts+ :pointer)
(defctype +keyhash+     :pointer)
(defctype +channel+     :pointer)

(defbitfield +TRACE-OPTIONS+
  (.TRANS.    2)
  (.KEX.      4)
  (.AUTH.     8)
  (.CONN.     16)
  (.SCP.      32)
  (.SFTP.     64)
  (.ERROR.    128)
  (.PUBLICKEY 256)
  (.SOCKET    512))

(defbitfield +known-hosts-flags+
  (.type-plain. 1)
  (.type-sha1.  2)
  (.raw.        65536)
  (.base64.     131072)
  (.rsa1.       262144)
  (.ssh.        524288))

(defcstruct +known-host+
  (magic :unsigned-int)
  (node  :pointer)
  (name  :string)
  (key   :string)
  (type  +known-hosts-flags+))

(defcstruct +kbd-prompt+
  (text    :pointer)
  (length  :unsigned-int)
  (echo    :unsigned-char))

(defcstruct +kbd-response+
  (text    :pointer)
  (length  :unsigned-int))

(defstruct key
  (data 0 :read-only t)
  (size 0 :read-only t)
  (type 0 :read-only t))

(define-condition ssh-generic-error (error)
  ((message :type     string
            :initarg  :message
            :accessor message)
   (code    :type     +ERROR-CODE+
            :accessor code
            :initarg  :code)))

(defmethod print-object ((sge ssh-generic-error) stream)
  (format stream "Libssh2: ~a (~a)" (message sge) (code sge)))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defvar *default-errors-list*
    (cons :UNKNOWN
     (remove :ERROR-NONE
             (foreign-enum-keyword-list '+ERROR-CODE+)))))

(defvar *errors-list* *default-errors-list*)

(define-condition libssh2-invalid-error-code (error)
  ((code :type     keyword
         :accessor code
         :initarg  :code)))
