(function () {
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  if (mobileMenuBtn) {
    mobileMenuBtn.addEventListener('click', function () {
      const nav = document.querySelector('.nav-links');
      if (nav) {
        nav.classList.toggle('open');
      }
    });
  }

  const tabButtons = document.querySelectorAll('.tab-btn');
  if (tabButtons.length) {
    const panels = {};
    tabButtons.forEach(button => {
      const tab = button.getAttribute('data-tab');
      if (tab) {
        const panel = document.getElementById(`tab-${tab}`);
        if (panel) {
          panels[tab] = panel;
        }
      }
    });

    function setActive(tab) {
      tabButtons.forEach(button => {
        const isActive = button.getAttribute('data-tab') === tab;
        button.classList.toggle('active', isActive);
        button.setAttribute('aria-selected', isActive ? 'true' : 'false');
      });
      Object.keys(panels).forEach(key => {
        const panel = panels[key];
        const isActive = key === tab;
        panel.classList.toggle('active', isActive);
        panel.setAttribute('aria-hidden', isActive ? 'false' : 'true');
      });
    }

    tabButtons.forEach(button => {
      button.addEventListener('click', function () {
        const tab = button.getAttribute('data-tab');
        if (tab) {
          setActive(tab);
        }
      });
    });
  }

  const confirmForms = document.querySelectorAll('form[data-confirm]');
  confirmForms.forEach(form => {
    form.addEventListener('submit', function (event) {
      const message = form.getAttribute('data-confirm');
      if (message && !window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  const fallbackImages = document.querySelectorAll('img[data-fallback-src]');
  fallbackImages.forEach(img => {
    img.addEventListener('error', function () {
      const fallback = img.getAttribute('data-fallback-src');
      if (fallback && img.src !== fallback) {
        img.src = fallback;
      }
    });
  });

  const paymentTabs = document.querySelectorAll('.payment-tab');
  if (paymentTabs.length) {
    const paymentContents = document.querySelectorAll('.payment-content');
    paymentTabs.forEach(tab => {
      tab.addEventListener('click', function () {
        const method = this.getAttribute('data-payment');
        paymentTabs.forEach(t => t.classList.remove('active'));
        paymentContents.forEach(c => c.classList.remove('active'));
        this.classList.add('active');
        const activeContent = document.querySelector(`.payment-content[data-payment="${method}"]`);
        if (activeContent) {
          activeContent.classList.add('active');
        }
        const paymentMethodInput = document.getElementById('payment_method');
        if (paymentMethodInput) {
          paymentMethodInput.value = method;
        }
      });
    });
  }

  const cardNumber = document.getElementById('card_number');
  if (cardNumber) {
    cardNumber.addEventListener('input', function (event) {
      let val = event.target.value.replace(/\D/g, '').substring(0, 16);
      let formatted = val.match(/.{1,4}/g)?.join('-') || '';
      event.target.value = formatted;
    });
  }

  const cardExpiry = document.getElementById('card_expiry');
  if (cardExpiry) {
    cardExpiry.addEventListener('input', function (event) {
      let val = event.target.value.replace(/\D/g, '').substring(0, 4);
      if (val.length > 2) {
        val = val.substring(0, 2) + '/' + val.substring(2);
      }
      event.target.value = val;
    });
  });
})();
