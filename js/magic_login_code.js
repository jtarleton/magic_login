/**
 * @file
 * The sign-in code field.
 *
 * One real input (autocomplete="one-time-code"), so the phone's "From Mail" /
 * "Found in email" suggestion and a paste fill it in one go. Over it, six
 * digit boxes that mirror its value; the input itself stays on top, see-
 * through, so taps, the keyboard, autofill and screen readers all reach it.
 * Without this script the plain field still works.
 *
 * Keeps digits only, takes the code out of a pasted sentence ("Your code
 * is: 123456"), and submits the form once the whole code is in.
 *
 * The code field has focus when the page opens, so the Altcha widget's
 * "check on focus" may never fire; the check is started here as soon as the
 * page loads, and an automatic submit waits for it to finish.
 */
((Drupal, once) => {
  const ready = (widget) =>
    !widget || (widget.getState && widget.getState() === 'verified');

  // Starts the Altcha check (if there is one) and resolves when it passes,
  // or after a timeout, leaving the server to say if it did not.
  const verified = (widget) =>
    new Promise((resolve) => {
      if (ready(widget)) {
        resolve();
        return;
      }
      // A call made before the widget has finished setting itself up is
      // ignored, so it is repeated (once a second) until the check is running.
      let lastCall = 0;
      const kick = () => {
        if (
          widget.verify &&
          widget.getState &&
          widget.getState() === 'unverified' &&
          Date.now() - lastCall > 1000
        ) {
          lastCall = Date.now();
          widget.verify();
        }
      };
      kick();
      const started = Date.now();
      const timer = setInterval(() => {
        if (ready(widget) || Date.now() - started > 15000) {
          clearInterval(timer);
          resolve();
          return;
        }
        kick();
      }, 150);
    });

  /**
   * The code in some text.
   *
   * A run of exactly `length` digits if there is one (so a pasted email
   * sentence works), else all its digits.
   *
   * @param {string} text
   *   Typed or pasted text.
   * @param {number} length
   *   The number of digits in a code.
   *
   * @return {string}
   *   At most `length` digits.
   */
  const extract = (text, length) => {
    const run = String(text).match(
      new RegExp(`(?:^|\\D)(\\d{${length}})(?!\\d)`),
    );
    return (run ? run[1] : String(text).replace(/\D+/g, '')).slice(0, length);
  };

  /**
   * Builds the digit boxes around the input.
   *
   * @param {HTMLInputElement} input
   *   The code field.
   * @param {number} length
   *   The number of digits in a code.
   *
   * @return {Function}
   *   Repaints the boxes from the field's value.
   */
  const boxes = (input, length) => {
    const wrap = document.createElement('div');
    wrap.className = 'magic-login-otp';
    wrap.style.setProperty('--magic-login-otp-length', String(length));
    const cells = document.createElement('div');
    cells.className = 'magic-login-otp__cells';
    cells.setAttribute('aria-hidden', 'true');
    for (let i = 0; i < length; i += 1) {
      const cell = document.createElement('span');
      cell.className = 'magic-login-otp__cell';
      if (i === length / 2) {
        // A gap between the two halves, like the code in the email.
        cell.classList.add('magic-login-otp__cell--split');
      }
      cells.appendChild(cell);
    }
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(cells);
    wrap.appendChild(input);
    input.classList.add('magic-login-otp__input');
    input.removeAttribute('placeholder');
    if (input.classList.contains('error')) {
      wrap.classList.add('is-error');
    }

    const paint = () => {
      const value = input.value;
      const focused = document.activeElement === input;
      const at = Math.min(value.length, length - 1);
      [...cells.children].forEach((cell, i) => {
        cell.textContent = value[i] || '';
        cell.classList.toggle('is-filled', i < value.length);
        cell.classList.toggle(
          'is-current',
          focused && i === at && !(value.length === length),
        );
      });
      wrap.classList.toggle('is-focused', focused);
      wrap.classList.toggle('is-complete', value.length === length);
    };
    ['focus', 'blur'].forEach((type) => input.addEventListener(type, paint));
    // Keep the caret at the end: the boxes only show a code typed in order.
    input.addEventListener('keyup', () => {
      input.setSelectionRange(input.value.length, input.value.length);
    });
    return paint;
  };

  Drupal.behaviors.magicLoginCode = {
    attach(context) {
      once('magic-login-code', 'input[data-magic-login-code]', context).forEach(
        (input) => {
          const length = parseInt(input.dataset.magicLoginCode, 10) || 6;
          const form = input.form;
          const widget = form ? form.querySelector('altcha-widget') : null;
          const paint = boxes(input, length);
          let sent = false;

          if (widget && window.customElements) {
            window.customElements
              .whenDefined('altcha-widget')
              .then(() => verified(widget));
          }

          const settle = () => {
            const digits = extract(input.value, length);
            if (digits !== input.value) {
              input.value = digits;
            }
            paint();
            if (!sent && digits.length === length && form) {
              sent = true;
              input.closest('.magic-login-otp').classList.remove('is-error');
              verified(widget).then(() => {
                const button = form.querySelector(
                  '[name="magic_login_verify"]',
                );
                // requestSubmit() names the pressed button and runs the form's
                // own submit handlers.
                if (form.requestSubmit) {
                  form.requestSubmit(button || undefined);
                } else if (button) {
                  button.click();
                }
              });
              // Allow another try if the page did not move on.
              setTimeout(() => {
                sent = false;
              }, 4000);
            }
          };

          // A paste replaces the whole code, wherever the caret was.
          input.addEventListener('paste', (event) => {
            const text = (event.clipboardData || window.clipboardData)?.getData(
              'text',
            );
            if (text) {
              event.preventDefault();
              input.value = extract(text, length);
              settle();
            }
          });
          input.addEventListener('input', settle);
          paint();
          // A code already there (the browser restored it, or autofill was
          // quicker than this script).
          if (input.value) {
            settle();
          }
        },
      );
    },
  };
})(Drupal, once);
