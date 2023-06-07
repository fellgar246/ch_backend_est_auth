const socket = io();


const addForm = document.querySelector('#addForm');

//Para crear nuevo Producto
addForm.addEventListener('submit', (e) => {
    e.preventDefault()
    let newProduct = {
        "title": addForm['title'].value,
        "description": addForm['description'].value,
        "code": addForm['code'].value,
        "price": addForm['price'].value,
        "stock": addForm['stock'].value,
        "category": addForm['category'].value
    }
    socket.emit("client:addProduct", newProduct )
    addForm['title'].value = "";
    addForm['description'].value = "";
    addForm['code'].value = "";
    addForm['price'].value = "";
    addForm['stock'].value = "";
    addForm['category'].value = "";

})


const deleteInput = document.querySelector('#deleteInput');
const deleteButton = document.querySelector('#deleteButton');

//Para eliminar Producto
deleteButton.addEventListener("click", (e) => {
    let product = parseInt(deleteInput.value)
    socket.emit("client:deleteProduct", product )

    deleteInput.value = ""
})

//Mostar Productos
socket.on('server:loadProducts',data =>{
    const productsList = document.querySelector('#products');

    let content= "";
    data.forEach(product=>{
        content+=`
        <div class=productCard >
            <h4>id ${product._id} - ${product.title} </h4>
            <p>Code: ${product.code}</p>
            <p>Price: $${product.price}</p>
            <p>Stock: ${product.stock}pz</p>
            <p>Category: ${product.category}</p>
            <p>thumbnail: none</p>
        </div>   
        `
    })
    productsList.innerHTML = content; 
})

