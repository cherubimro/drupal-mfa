/**
 * @file
 * WebAuthn/TOTP 2FA/MFA browser-side logic for Drupal.
 *
 * Ported from Roundcube WebAuthn plugin, extended with TOTP and MFA support.
 * Compatible with Drupal 9 (jquery.once) and 10+ (core/once).
 */

(function ($, Drupal, drupalSettings, once) {
  'use strict';

  // Track which methods have been completed client-side (mirrors server session).
  var completedMethods = [];

  // ---- Base64url helpers ----

  function b64urlEncode(buffer) {
    var bytes = new Uint8Array(buffer);
    var str = '';
    for (var i = 0; i < bytes.byteLength; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function b64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
      str += '=';
    }
    var binary = atob(str);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // ---- MFA step indicator helpers ----

  function markStepDone(method) {
    var stepEl = document.getElementById('webauthn-step-' + method);
    if (stepEl) {
      stepEl.classList.add('webauthn-verify__step--done');
      var indicator = stepEl.querySelector('.webauthn-verify__step-indicator');
      if (indicator) {
        indicator.textContent = '\u2713'; // checkmark
      }
    }
  }

  function markStepActive(method) {
    var stepEl = document.getElementById('webauthn-step-' + method);
    if (stepEl) {
      stepEl.classList.add('webauthn-verify__step--active');
    }
  }

  function markStepInactive(method) {
    var stepEl = document.getElementById('webauthn-step-' + method);
    if (stepEl) {
      stepEl.classList.remove('webauthn-verify__step--active');
    }
  }

  // ---- Verify mode (2FA/MFA gate) ----

  function initVerifyMode() {
    var settings = drupalSettings.webauthn || {};
    var hasWebauthn = settings.hasWebauthn;
    var hasTotp = settings.hasTotp;
    var mode = settings.verificationMode || 'any';

    // Restore completed methods from server-side session (handles page refresh).
    completedMethods = settings.completedMethods || [];

    var keySection = document.getElementById('webauthn-key-section');
    var totpSection = document.getElementById('webauthn-totp-section');
    var methodSwitch = document.getElementById('webauthn-method-switch');
    var mfaSteps = document.getElementById('webauthn-mfa-steps');

    if (mode === 'all' && hasWebauthn && hasTotp) {
      // MFA mode: both required. Show step indicators.
      if (mfaSteps) mfaSteps.style.display = '';

      // Mark already-completed steps.
      for (var i = 0; i < completedMethods.length; i++) {
        markStepDone(completedMethods[i]);
      }

      // Determine which step to show next.
      var webauthnDone = completedMethods.indexOf('webauthn') !== -1;
      var totpDone = completedMethods.indexOf('totp') !== -1;

      if (!webauthnDone) {
        markStepActive('webauthn');
        if (keySection) keySection.style.display = '';
        startAssertion();
      }
      else if (!totpDone) {
        markStepActive('totp');
        if (totpSection) totpSection.style.display = '';
        var msgEl = document.getElementById('webauthn-message');
        if (msgEl) {
          msgEl.textContent = Drupal.t('Now enter the code from your authenticator app.');
        }
        var codeInput = document.getElementById('webauthn-totp-code');
        if (codeInput) codeInput.focus();
      }
    }
    else if (mode === 'any' && hasWebauthn && hasTotp) {
      // 2FA mode with both methods: show WebAuthn first with switch link.
      if (keySection) keySection.style.display = '';
      if (methodSwitch) methodSwitch.style.display = '';
      startAssertion();
    }
    else if (hasWebauthn) {
      if (keySection) keySection.style.display = '';
      startAssertion();
    }
    else if (hasTotp) {
      if (totpSection) totpSection.style.display = '';
      var msgEl = document.getElementById('webauthn-message');
      if (msgEl) {
        msgEl.textContent = Drupal.t('Enter the code from your authenticator app.');
      }
    }

    // Method switcher links (only used in "any" mode).
    var switchToTotp = document.getElementById('webauthn-switch-to-totp');
    var switchToKey = document.getElementById('webauthn-switch-to-key');

    if (switchToTotp) {
      switchToTotp.addEventListener('click', function (e) {
        e.preventDefault();
        if (keySection) keySection.style.display = 'none';
        if (totpSection) totpSection.style.display = '';
        switchToTotp.style.display = 'none';
        if (switchToKey) switchToKey.style.display = '';
        var msgEl = document.getElementById('webauthn-message');
        if (msgEl) {
          msgEl.textContent = Drupal.t('Enter the code from your authenticator app.');
        }
        var errEl = document.getElementById('webauthn-error');
        if (errEl) errEl.style.display = 'none';
        var codeInput = document.getElementById('webauthn-totp-code');
        if (codeInput) codeInput.focus();
      });
    }

    if (switchToKey) {
      switchToKey.addEventListener('click', function (e) {
        e.preventDefault();
        if (totpSection) totpSection.style.display = 'none';
        if (keySection) keySection.style.display = '';
        switchToKey.style.display = 'none';
        if (switchToTotp) switchToTotp.style.display = '';
        startAssertion();
      });
    }

    // Retry button.
    var retryBtn = document.getElementById('webauthn-retry-btn');
    if (retryBtn) {
      retryBtn.addEventListener('click', function (e) {
        e.preventDefault();
        startAssertion();
      });
    }

    // TOTP verify submit.
    var totpSubmit = document.getElementById('webauthn-totp-submit');
    if (totpSubmit) {
      totpSubmit.addEventListener('click', function (e) {
        e.preventDefault();
        submitTotpVerify();
      });
    }

    // Allow Enter key in TOTP input.
    var totpInput = document.getElementById('webauthn-totp-code');
    if (totpInput) {
      totpInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          submitTotpVerify();
        }
      });
    }
  }

  function startAssertion() {
    var msgEl = document.getElementById('webauthn-message');
    var errEl = document.getElementById('webauthn-error');
    var retryEl = document.getElementById('webauthn-retry-btn');

    if (msgEl) {
      msgEl.textContent = Drupal.t('Tap your security key or use your passkey...');
    }
    if (errEl) {
      errEl.textContent = '';
      errEl.style.display = 'none';
    }
    if (retryEl) {
      retryEl.style.display = 'none';
    }

    $.ajax({
      url: drupalSettings.webauthn.assertOptionsUrl,
      type: 'GET',
      dataType: 'json',
      success: function (response) {
        handleAssertOptions(response);
      },
      error: function () {
        showError(Drupal.t('Failed to get challenge from server.'));
      }
    });
  }

  function handleAssertOptions(response) {
    if (!response.success) {
      showError(response.error || Drupal.t('Failed to get challenge.'));
      return;
    }

    var options = response.options;

    if (options.publicKey && options.publicKey.challenge) {
      options.publicKey.challenge = b64urlDecode(options.publicKey.challenge);
    }

    if (options.publicKey && options.publicKey.allowCredentials) {
      for (var i = 0; i < options.publicKey.allowCredentials.length; i++) {
        options.publicKey.allowCredentials[i].id = b64urlDecode(
          options.publicKey.allowCredentials[i].id
        );
      }
    }

    navigator.credentials.get(options)
      .then(function (assertion) {
        var data = {
          credentialId: b64urlEncode(assertion.rawId),
          clientDataJSON: b64urlEncode(assertion.response.clientDataJSON),
          authenticatorData: b64urlEncode(assertion.response.authenticatorData),
          signature: b64urlEncode(assertion.response.signature)
        };

        $.ajax({
          url: drupalSettings.webauthn.assertVerifyUrl,
          type: 'POST',
          contentType: 'application/json',
          data: JSON.stringify(data),
          dataType: 'json',
          success: function (result) {
            handleVerifyResult(result, 'webauthn');
          },
          error: function (xhr) {
            var msg = Drupal.t('Verification failed.');
            try {
              var err = JSON.parse(xhr.responseText);
              if (err.error) msg = err.error;
            } catch (e) {}
            showError(msg);
          }
        });
      })
      .catch(function (err) {
        showError(err.message || Drupal.t('Authentication cancelled.'));
      });
  }

  function submitTotpVerify() {
    var codeInput = document.getElementById('webauthn-totp-code');
    var code = codeInput ? codeInput.value.trim() : '';

    if (!code || code.length !== 6) {
      showError(Drupal.t('Please enter a 6-digit code.'));
      return;
    }

    var errEl = document.getElementById('webauthn-error');
    if (errEl) errEl.style.display = 'none';
    var msgEl = document.getElementById('webauthn-message');
    if (msgEl) msgEl.textContent = Drupal.t('Verifying...');

    $.ajax({
      url: drupalSettings.webauthn.totpVerifyUrl,
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({code: code}),
      dataType: 'json',
      success: function (result) {
        handleVerifyResult(result, 'totp');
      },
      error: function (xhr) {
        var msg = Drupal.t('Verification failed.');
        try {
          var err = JSON.parse(xhr.responseText);
          if (err.error) msg = err.error;
        } catch (e) {}
        showError(msg);
        if (msgEl) msgEl.textContent = Drupal.t('Enter the code from your authenticator app.');
        if (codeInput) {
          codeInput.value = '';
          codeInput.focus();
        }
      }
    });
  }

  /**
   * Handles a verification response — either final redirect or partial (MFA).
   */
  function handleVerifyResult(response, method) {
    if (!response.success) {
      showError(response.error || Drupal.t('Verification failed.'));
      return;
    }

    // Final: all methods verified, redirect.
    if (response.redirect) {
      var msgEl = document.getElementById('webauthn-message');
      if (msgEl) msgEl.textContent = Drupal.t('Verification successful! Redirecting...');
      window.location.href = response.redirect;
      return;
    }

    // Partial: MFA mode, more factors needed.
    if (response.partial) {
      completedMethods.push(method);
      markStepDone(method);
      markStepInactive(method);

      var keySection = document.getElementById('webauthn-key-section');
      var totpSection = document.getElementById('webauthn-totp-section');
      var errEl = document.getElementById('webauthn-error');
      if (errEl) errEl.style.display = 'none';

      // Show the next required method.
      var remaining = response.remaining || [];
      if (remaining.indexOf('webauthn') !== -1) {
        markStepActive('webauthn');
        if (totpSection) totpSection.style.display = 'none';
        if (keySection) keySection.style.display = '';
        startAssertion();
      }
      else if (remaining.indexOf('totp') !== -1) {
        markStepActive('totp');
        if (keySection) keySection.style.display = 'none';
        if (totpSection) totpSection.style.display = '';
        var msgEl = document.getElementById('webauthn-message');
        if (msgEl) msgEl.textContent = Drupal.t('Security key verified! Now enter the code from your authenticator app.');
        var codeInput = document.getElementById('webauthn-totp-code');
        if (codeInput) {
          codeInput.value = '';
          codeInput.focus();
        }
      }
    }
  }

  function showError(message) {
    var errEl = document.getElementById('webauthn-error');
    var retryEl = document.getElementById('webauthn-retry-btn');
    var msgEl = document.getElementById('webauthn-message');

    if (msgEl) msgEl.textContent = Drupal.t('Verification failed.');
    if (errEl) {
      errEl.textContent = message;
      errEl.style.display = 'block';
    }
    if (retryEl) retryEl.style.display = '';
  }

  // ---- Settings mode (key management + TOTP setup) ----

  function registerKey() {
    var description = prompt(Drupal.t('Enter a name for this security key:'), 'My Security Key');
    if (description === null) return;

    description = description.trim() || 'Security Key';

    var msgEl = document.getElementById('webauthn-settings-message');
    if (msgEl) {
      msgEl.textContent = Drupal.t('Touch your security key to register it...');
      msgEl.style.display = 'block';
    }

    $.ajax({
      url: drupalSettings.webauthn.registerOptionsUrl +
        (drupalSettings.webauthn.registerOptionsUrl.indexOf('?') !== -1 ? '&' : '?') +
        'description=' + encodeURIComponent(description),
      type: 'GET',
      dataType: 'json',
      success: function (response) {
        handleRegisterOptions(response);
      },
      error: function () {
        showSettingsMessage(Drupal.t('Failed to get registration options.'), 'error');
      }
    });
  }

  function handleRegisterOptions(response) {
    if (!response.success) {
      showSettingsMessage(response.error || Drupal.t('Failed to get registration options.'), 'error');
      return;
    }

    var options = response.options;

    if (options.publicKey && options.publicKey.challenge) {
      options.publicKey.challenge = b64urlDecode(options.publicKey.challenge);
    }
    if (options.publicKey && options.publicKey.user && options.publicKey.user.id) {
      options.publicKey.user.id = b64urlDecode(options.publicKey.user.id);
    }
    if (options.publicKey && options.publicKey.excludeCredentials) {
      for (var i = 0; i < options.publicKey.excludeCredentials.length; i++) {
        options.publicKey.excludeCredentials[i].id = b64urlDecode(
          options.publicKey.excludeCredentials[i].id
        );
      }
    }

    navigator.credentials.create(options)
      .then(function (credential) {
        var transports = '';
        if (credential.response.getTransports) {
          transports = credential.response.getTransports().join(',');
        }

        var data = {
          clientDataJSON: b64urlEncode(credential.response.clientDataJSON),
          attestationObject: b64urlEncode(credential.response.attestationObject),
          transports: transports
        };

        $.ajax({
          url: drupalSettings.webauthn.registerVerifyUrl,
          type: 'POST',
          contentType: 'application/json',
          data: JSON.stringify(data),
          dataType: 'json',
          success: function (result) {
            if (result.success) {
              showSettingsMessage(Drupal.t('Security key registered successfully!'), 'status');
              window.location.reload();
            } else {
              showSettingsMessage(result.error || Drupal.t('Registration failed.'), 'error');
            }
          },
          error: function (xhr) {
            var msg = Drupal.t('Registration failed.');
            try {
              var err = JSON.parse(xhr.responseText);
              if (err.error) msg = err.error;
            } catch (e) {}
            showSettingsMessage(msg, 'error');
          }
        });
      })
      .catch(function (err) {
        showSettingsMessage(err.message || Drupal.t('Registration cancelled.'), 'error');
      });
  }

  function deleteKey(id) {
    if (!confirm(Drupal.t('Are you sure you want to delete this security key?'))) return;

    $.ajax({
      url: drupalSettings.webauthn.deleteUrl,
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({id: id}),
      dataType: 'json',
      success: function (response) {
        if (response.success) {
          window.location.reload();
        } else {
          showSettingsMessage(response.error || Drupal.t('Delete failed.'), 'error');
        }
      },
      error: function (xhr) {
        var msg = Drupal.t('Delete failed.');
        try {
          var err = JSON.parse(xhr.responseText);
          if (err.error) msg = err.error;
        } catch (e) {}
        showSettingsMessage(msg, 'error');
      }
    });
  }

  function toggle2fa(enabled) {
    $.ajax({
      url: drupalSettings.webauthn.toggleUrl,
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({enabled: enabled ? 1 : 0}),
      dataType: 'json',
      success: function (response) {
        if (!response.success) {
          showSettingsMessage(response.error || Drupal.t('Toggle failed.'), 'error');
          var cb = document.getElementById('webauthn-toggle');
          if (cb) cb.checked = !cb.checked;
        }
      },
      error: function (xhr) {
        var msg = Drupal.t('Toggle failed.');
        try {
          var err = JSON.parse(xhr.responseText);
          if (err.error) msg = err.error;
        } catch (e) {}
        showSettingsMessage(msg, 'error');
        var cb = document.getElementById('webauthn-toggle');
        if (cb) cb.checked = !cb.checked;
      }
    });
  }

  // ---- TOTP settings functions ----

  function startTotpSetup() {
    showSettingsMessage(Drupal.t('Generating authenticator app setup...'), 'status');

    $.ajax({
      url: drupalSettings.webauthn.totpSetupUrl,
      type: 'GET',
      dataType: 'json',
      success: function (response) {
        if (!response.success) {
          showSettingsMessage(response.error || Drupal.t('Failed to start setup.'), 'error');
          return;
        }

        var setupEl = document.getElementById('webauthn-totp-setup');
        var qrEl = document.getElementById('webauthn-totp-qr');
        var secretEl = document.getElementById('webauthn-totp-secret');

        if (qrEl) qrEl.innerHTML = response.qrSvg;
        if (secretEl) secretEl.textContent = response.secret;
        if (setupEl) setupEl.style.display = '';

        var setupBtn = document.getElementById('webauthn-totp-setup-btn');
        if (setupBtn) setupBtn.style.display = 'none';

        showSettingsMessage(Drupal.t('Scan the QR code with your authenticator app, then enter the code below.'), 'status');
      },
      error: function () {
        showSettingsMessage(Drupal.t('Failed to start authenticator app setup.'), 'error');
      }
    });
  }

  function confirmTotpSetup() {
    var codeInput = document.getElementById('webauthn-totp-confirm-code');
    var code = codeInput ? codeInput.value.trim() : '';

    if (!code || code.length !== 6) {
      showSettingsMessage(Drupal.t('Please enter the 6-digit code from your authenticator app.'), 'error');
      return;
    }

    $.ajax({
      url: drupalSettings.webauthn.totpConfirmUrl,
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({code: code}),
      dataType: 'json',
      success: function (response) {
        if (response.success) {
          showSettingsMessage(Drupal.t('Authenticator app configured successfully!'), 'status');
          window.location.reload();
        } else {
          showSettingsMessage(response.error || Drupal.t('Confirmation failed.'), 'error');
          if (codeInput) codeInput.focus();
        }
      },
      error: function (xhr) {
        var msg = Drupal.t('Confirmation failed.');
        try {
          var err = JSON.parse(xhr.responseText);
          if (err.error) msg = err.error;
        } catch (e) {}
        showSettingsMessage(msg, 'error');
        if (codeInput) codeInput.focus();
      }
    });
  }

  function cancelTotpSetup() {
    var setupEl = document.getElementById('webauthn-totp-setup');
    if (setupEl) setupEl.style.display = 'none';
    var setupBtn = document.getElementById('webauthn-totp-setup-btn');
    if (setupBtn) setupBtn.style.display = '';
    var msgEl = document.getElementById('webauthn-settings-message');
    if (msgEl) msgEl.style.display = 'none';
  }

  function removeTotpSetup() {
    if (!confirm(Drupal.t('Are you sure you want to remove your authenticator app? You will no longer be able to use it for 2FA.'))) return;

    $.ajax({
      url: drupalSettings.webauthn.totpRemoveUrl,
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({}),
      dataType: 'json',
      success: function (response) {
        if (response.success) {
          showSettingsMessage(Drupal.t('Authenticator app removed.'), 'status');
          window.location.reload();
        } else {
          showSettingsMessage(response.error || Drupal.t('Remove failed.'), 'error');
        }
      },
      error: function (xhr) {
        var msg = Drupal.t('Remove failed.');
        try {
          var err = JSON.parse(xhr.responseText);
          if (err.error) msg = err.error;
        } catch (e) {}
        showSettingsMessage(msg, 'error');
      }
    });
  }

  function showSettingsMessage(message, type) {
    var msgEl = document.getElementById('webauthn-settings-message');
    if (msgEl) {
      msgEl.textContent = message;
      msgEl.className = 'webauthn-message webauthn-message--' + type;
      msgEl.style.display = 'block';
    }
  }

  // ---- Drupal behavior ----

  Drupal.behaviors.webauthn = {
    attach: function (context) {
      var settings = drupalSettings.webauthn || {};

      if (settings.mode === 'verify') {
        once('webauthn', '#webauthn-verify-wrapper', context).forEach(function () {
          if (!window.PublicKeyCredential && !settings.hasTotp) {
            var msgEl = document.getElementById('webauthn-message');
            if (msgEl) msgEl.textContent = Drupal.t('Your browser does not support WebAuthn/FIDO2.');
            return;
          }
          initVerifyMode();
        });
      }

      if (settings.mode === 'settings') {
        once('webauthn', '#webauthn-settings-wrapper', context).forEach(function (el) {
          if (!window.PublicKeyCredential) {
            var regBtn = document.getElementById('webauthn-register-btn');
            if (regBtn) {
              regBtn.disabled = true;
              regBtn.title = Drupal.t('Your browser does not support WebAuthn/FIDO2.');
            }
          }

          var regBtn = document.getElementById('webauthn-register-btn');
          if (regBtn && window.PublicKeyCredential) {
            regBtn.addEventListener('click', function (e) { e.preventDefault(); registerKey(); });
          }

          el.querySelectorAll('.webauthn-delete-btn').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
              e.preventDefault();
              deleteKey(parseInt(btn.getAttribute('data-credential-id'), 10));
            });
          });

          var toggleCb = document.getElementById('webauthn-toggle');
          if (toggleCb) {
            toggleCb.addEventListener('change', function () { toggle2fa(this.checked); });
          }

          var totpSetupBtn = document.getElementById('webauthn-totp-setup-btn');
          if (totpSetupBtn) {
            totpSetupBtn.addEventListener('click', function (e) { e.preventDefault(); startTotpSetup(); });
          }

          var totpConfirmBtn = document.getElementById('webauthn-totp-confirm-btn');
          if (totpConfirmBtn) {
            totpConfirmBtn.addEventListener('click', function (e) { e.preventDefault(); confirmTotpSetup(); });
          }

          var totpConfirmInput = document.getElementById('webauthn-totp-confirm-code');
          if (totpConfirmInput) {
            totpConfirmInput.addEventListener('keydown', function (e) {
              if (e.key === 'Enter') { e.preventDefault(); confirmTotpSetup(); }
            });
          }

          var totpCancelBtn = document.getElementById('webauthn-totp-cancel-btn');
          if (totpCancelBtn) {
            totpCancelBtn.addEventListener('click', function (e) { e.preventDefault(); cancelTotpSetup(); });
          }

          var totpRemoveBtn = document.getElementById('webauthn-totp-remove-btn');
          if (totpRemoveBtn) {
            totpRemoveBtn.addEventListener('click', function (e) { e.preventDefault(); removeTotpSetup(); });
          }
        });
      }
    }
  };

})(jQuery, Drupal, drupalSettings, once);
