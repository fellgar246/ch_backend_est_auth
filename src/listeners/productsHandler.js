import ProductsManager from "../dao/mongo/Managers/products.js";

const productService = new ProductsManager();

const registerProductsHandler = (io,socket) =>{

    const emitProducts = async() => {
        const products = await productService.getProducts()
        return products
    } 


   emitProducts()

    const newProduct = async (data) =>{
        await productService.createProduct(data)
    }

    const eraseProduct = async (data) => {
        await productService.deleteProduct(data)
    }

    io.emit('server:loadProducts', emitProducts)
    socket.on('client:addProduct', newProduct);
    socket.on('client:deleteProduct', eraseProduct);
} 

export default registerProductsHandler;