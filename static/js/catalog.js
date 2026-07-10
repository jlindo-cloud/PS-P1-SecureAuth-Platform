(function() {
  const searchInput = document.getElementById('searchInput');
  const filters = document.querySelectorAll('.filter-btn');
  const grid = document.getElementById('productsGrid');
  const cards = Array.from(grid.querySelectorAll('.product-card'));
  const noResults = document.getElementById('noResults');
  let activeCategory = 'all';

  function filterCards() {
    const term = searchInput.value.trim().toLowerCase();
    let visible = 0;
    cards.forEach(card => {
      const cat = card.getAttribute('data-category');
      const name = card.getAttribute('data-name');
      const matchesCategory = activeCategory === 'all' || cat === activeCategory;
      const matchesSearch = !term || name.includes(term);
      const show = matchesCategory && matchesSearch;
      card.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    noResults.style.display = visible === 0 ? 'block' : 'none';
  }

  filters.forEach(btn => {
    btn.addEventListener('click', () => {
      filters.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeCategory = btn.getAttribute('data-category');
      filterCards();
    });
  });

  if (searchInput) {
    searchInput.addEventListener('input', filterCards);
  }
})();
