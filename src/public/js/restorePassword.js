const form = document.getElementById('restoreForm');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  const user = {};
  data.forEach((value, key) => (user[key] = value));
  const response = await fetch('/api/sessions/restorePassword', {
    method: 'POST',
    body: JSON.stringify(user),
    headers: {
      'Content-Type': 'application/json',
    },
  });
  const responseData = await response.json();
  if (responseData.status === 'success') {
    window.location.replace('/login');
  }
});