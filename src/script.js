document.addEventListener('DOMContentLoaded', function () {
  const urlInput = document.getElementById('urlInput');
  const checkUrlBtn = document.getElementById('checkUrlBtn');
  const fileInput = document.getElementById('fileInput');
  const fileDropArea = document.getElementById('fileDropArea');
  const fileName = document.getElementById('fileName');
  const loadingIndicator = document.getElementById('loadingIndicator');
  const resultsContainer = document.getElementById('resultsContainer');

  checkUrlBtn.addEventListener('click', function () {
    const url = urlInput.value.trim();
    if (url) {
      checkUrl(url);
    } else {
      alert('Пожалуйста, введите URL для проверки');
    }
  });

  fileDropArea.addEventListener('click', function () {
    fileInput.click();
  });

  fileInput.addEventListener('change', function (e) {
    if (e.target.files.length) {
      handleFile(e.target.files[0]);
    }
  });

  fileDropArea.addEventListener('dragover', function (e) {
    e.preventDefault();
    fileDropArea.style.borderColor = '#4361ee';
    fileDropArea.style.backgroundColor = '#f0f4ff';
  });

  fileDropArea.addEventListener('dragleave', function () {
    fileDropArea.style.borderColor = '#ddd';
    fileDropArea.style.backgroundColor = 'transparent';
  });

  fileDropArea.addEventListener('drop', function (e) {
    e.preventDefault();
    fileDropArea.style.borderColor = '#ddd';
    fileDropArea.style.backgroundColor = 'transparent';

    if (e.dataTransfer.files.length) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  function handleFile(file) {
    fileName.textContent = `Выбран файл: ${file.name}`;
    checkFile(file);
  }

  async function checkUrl(url) {
    showLoading();
    clearResults();
    try {
      const res = await fetch('/.netlify/functions/check-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      if (data && Array.isArray(data.results)) {
        displayResults(data.results);
      } else {
        displayResults([{ service: 'Сервис', status: 'warning', details: 'Неожиданный ответ от сервера' }]);
      }
    } catch (e) {
      displayResults([{ service: 'Ошибка', status: 'unsafe', details: e.message }]);
    } finally {
      hideLoading();
    }
  }

  async function checkFile(file) {
    showLoading();
    clearResults();
    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch('/.netlify/functions/check-file', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (data && Array.isArray(data.results)) {
        displayResults(data.results);
      } else {
        displayResults([{ service: 'VirusTotal', status: 'warning', details: 'Репорт ожидается. Попробуйте позже обновить страницу.' }]);
      }
    } catch (e) {
      displayResults([{ service: 'Ошибка', status: 'unsafe', details: e.message }]);
    } finally {
      hideLoading();
    }
  }

  function showLoading() {
    loadingIndicator.style.display = 'block';
  }

  function hideLoading() {
    loadingIndicator.style.display = 'none';
  }

  function clearResults() {
    resultsContainer.innerHTML = '';
  }

  function displayResults(results) {
    results.forEach(result => {
      const resultItem = document.createElement('div');
      resultItem.className = 'result-item';

      const statusClass = result.status === 'safe' ? 'safe' :
        result.status === 'unsafe' ? 'unsafe' : 'warning';

      resultItem.innerHTML = `
        <div class="result-title">
          <div class="result-service">
            ${getServiceIcon(result.service)}
            ${result.service}
          </div>
          <span class="result-status ${statusClass}">
            ${getStatusText(result.status)}
          </span>
        </div>
        <div class="result-details">
          ${result.details || ''}
        </div>
      `;

      resultsContainer.appendChild(resultItem);
    });
  }

  function getServiceIcon(service) {
    const icons = {
      'Google Safe Browsing': '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
      'VirusTotal': '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 16a6 6 0 0 1-6-6c0-1.5.5-2 2-2h8c1.5 0 2 .5 2 2a6 6 0 0 1-6 6z"></path></svg>',
      'PhishTank': '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>',
      'OpenPhish': '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>',
      'Сервис': '',
      'Ошибка': ''
    };
    return icons[service] || '';
  }

  function getStatusText(status) {
    const statusText = {
      'safe': 'Безопасно',
      'unsafe': 'Опасность',
      'warning': 'Предупреждение'
    };
    return statusText[status] || status;
  }
});
