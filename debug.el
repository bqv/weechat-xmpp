(let ((vterm-shell "/bin/sh -c 'trap \"\" SIGINT ; read < /dev/zero'"))
  (with-current-buffer (vterm t)
    (let ((process (get-buffer-process (current-buffer))))
      (unless (and (boundp 'gud-comint-buffer) gud-comint-buffer)
        (gdb (string-join `("gdb" "-i=mi"
                            "-ex 'handle SIGPIPE nostop noprint pass'"
                            ,(concat "--args weechat -a -P alias,buflist,exec,irc,"
                                     (expand-file-name "xmpp.so" (projectile-project-root))
                                     "; /debug tags"))
                          " ")))
      (dolist (line
               (list (concat "tty " (process-tty-name process))
                     "set env TERM=xterm-256color"))
        (comint-send-string (get-buffer-process gud-comint-buffer)
                            (concat line "\n"))))))
