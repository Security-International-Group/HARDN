# tims report (staging)
- Report date: 10/13/2025
- Reported by:


1. Report Summary
- Brief title: Testing and polishing
- Short description: I wanted to again test the entry point and make sure the UX was seamless. Alongside that, wanted to mirror the gui terminla to a native terminal output to match data output, success. 
- missing app image for native env
- missing gui logo top left
- dependacies would splatter the terminal if they were missing

2. Environment
- machine name: ubunutu 24.04
- HARDN version: v0.4.27
- Bare Metal

3. Preconditions
- Installed from: clone from git, local to machine
- Services enabled (hardn.service, legion-daemon.service, hardn-api.service, hardn-monitor.service): ALL
- Any non-default settings: i dsabled apparmor enforce to allow apps just for testing 

4. Steps to Reproduce
- Step 1: using sudo make build for review
- Step 2: logging the diff of each file with tested updates
- Step 3: tetsing and validation success

5. Expected Behavior:
- Seamless UX with a good simple presentaiton layer, no login issues and reboot fine. 


6. Actual Result
- What happened instead: WE MUST mention apparmor enforce mode and whay works and doesnt. And provide a a "COMPLAIN" script i think, one single command. 
- Error messages (copy/paste): the hardn-gui.rs error is fixed, no errors. 

7. Logs and Artifacts
- Relevant journal logs:
  - journalctl -u hardn.service --since "<>"
  - journalctl -u legion-daemon.service --since "<time>"
  - journalctl -u hardn-api.service --since "<time>"
  - journalctl -u hardn-monitor.service --since "<time>"
- Attach snippets or files if possible

- GUI "No local app" after postint
- I did change the postint and hardn-gui.desktop for package entry and not makefile entry
```
ICON_SRC="/usr/share/pixmaps/hardn-gui.jpeg"
        if [ -f "${ICON_SRC}" ]; then
            TARGET_USER="${SUDO_USER:-}"
            if [ -z "${TARGET_USER}" ] || [ "${TARGET_USER}" = "root" ]; then
                TARGET_USER=$(logname 2>/dev/null || true)
            fi

            if [ -n "${TARGET_USER}" ] && getent passwd "${TARGET_USER}" >/dev/null; then
                TARGET_HOME=$(getent passwd "${TARGET_USER}" | cut -d: -f6)
                if [ -n "${TARGET_HOME}" ] && [ -d "${TARGET_HOME}" ]; then
                    DESKTOP_DIR="${TARGET_HOME}/.local/share/applications"
                    ICON_DIR="${TARGET_HOME}/.local/share/icons"
                    DESKTOP_PATH="${DESKTOP_DIR}/hardn-gui.desktop"
                    ICON_DEST="${ICON_DIR}/hardn-gui.jpeg"

                    install -d -m 755 -o "${TARGET_USER}" -g "${TARGET_USER}" "${DESKTOP_DIR}" "${ICON_DIR}"
                    install -m 644 -o "${TARGET_USER}" -g "${TARGET_USER}" "${ICON_SRC}" "${ICON_DEST}"
                    cat <<EOF > "${DESKTOP_PATH}"
[Desktop Entry]
Type=Application
Name=HARDN Control Center
Comment=Launch the HARDN monitoring console
Exec=/usr/bin/hardn-gui
Icon=${ICON_DEST}
Terminal=false
Categories=Security;System;
StartupNotify=true
EOF
                    chown "${TARGET_USER}:${TARGET_USER}" "${DESKTOP_PATH}" "${ICON_DEST}" || true
                    echo "HARDN desktop launcher deployed for ${TARGET_USER}."
                else
                    echo "HARDN desktop launcher skipped: unable to resolve home for ${TARGET_USER}."
                fi
            else
                echo "HARDN desktop launcher skipped: no non-root sudo user detected."
            fi
        fi
  ```

- GUI issues: see `git diff` of the updates for the missing gui image on SIEM tool. 
```
      header_box.set_margin_end(8);
         header_box.add_css_class("box-header");
         let logo_path_candidates = [
-            "/usr/share/hardn/docs/IMG_1233.jpeg",
-            "/usr/share/pixmaps/hardn.png",
-            "/usr/share/pixmaps/hardn.jpg",
-            "./docs/assets/IMG_1233.jpeg",
+            std::env::var("HARDN_GUI_LOGO").ok(),
+            Some("/usr/share/pixmaps/hardn.png".to_string()),
+            Some("/usr/share/pixmaps/hardn.jpg".to_string()),
+            Some("/usr/share/hardn/docs/IMG_1233.jpeg".to_string()),
+            Some("/usr/share/hardn/hardn-logo.png".to_string()),
+            Some("./docs/assets/IMG_1233.jpeg".to_string()),
         ];
```

- **TOOLS TESTS**
- 

8. Severity
- Low / Medium / High / Critical
- Impact (functional, performance, security, packaging):

9. Workarounds
- Any known temporary mitigations:

10. Notes
- Additional context:
- Related issues/PRs:
