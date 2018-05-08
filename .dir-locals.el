;;; Directory Local Variables
;;; For more information see (info "(emacs) Directory Variables")

((c-mode
  (eval . (setq-local flycheck-clang-include-path
                      (list (expand-file-name "libwebsockets/include" (projectile-project-root))
                            (expand-file-name "json-c" (projectile-project-root)))))
  (eval . (setq-local company-clang-arguments
                      (list (concat "-I" (expand-file-name "libwebsockets/include" (projectile-project-root)))
                            (concat "-I" (expand-file-name "json-c" (projectile-project-root))))))
  (flycheck-clang-warnings . ("all" "extra" "error-implicit-function-declaration" "no-missing-field-initializers"))
  (flycheck-clang-language-standard . "gnu99")
  (flycheck-checker . c/c++-clang)
  (projectile-project-compilation-cmd . "scan-build-3.8 make -j8")))

