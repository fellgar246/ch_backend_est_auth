const form = document.getElementById('loginForm');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  const user = {};
  data.forEach((value, key) => (user[key] = value));
  const response = await fetch('/api/sessions/jwtLogin', {
    method: 'POST',
    body: JSON.stringify(user),
    headers: {
      'Content-Type': 'application/json',
    },
  });
  const responseData = await response.json();
  if (responseData.status === 'success') {
    //window.location.replace('/products');
    localStorage.setItem('accessToken', responseData.accessToken)
  }
});

// form.addEventListener('submit', async (event) => {
//   event.preventDefault();
//   const data = new FormData(form);
//   const user = {};
//   data.forEach((value, key) => (user[key] = value));
//   const response = await fetch('/api/sessions/login', {
//     method: 'POST',
//     body: JSON.stringify(user),
//     headers: {
//       'Content-Type': 'application/json',
//     },
//   });
//   const responseData = await response.json();
//   if (responseData.status === 'success') {
//     window.location.replace('/products');
//   }
// });