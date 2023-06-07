const socket = io();


function addToCart(productId) {
    socket.emit("client:addToCart", productId )    
}

function deleteToCart(productId) {
    socket.emit("client:deleteToCart", productId )    
}


const form = document.getElementById('logoutButton');

form.addEventListener('click', async (event) => {

  const response = await fetch('/api/sessions/logout', {
    method: 'GET'
  });
  const responseData = await response.json();
  if (responseData.status === 'success') {
    window.location.replace('/login');
  }
});