import cartsManager from '../dao/mongo/Managers/carts.js';

const cartService = new cartsManager();

const registerCartsHandler = (io,socket) =>{

    const addToCart = async (data) =>{
        await cartService.postCartProduct("6471391c122af8c6505d1374", data, 1);
    }

    const deleteToCart = async (data) =>{
        await cartService.deleleProdByCart("6471391c122af8c6505d1374", data);
    }

    socket.on('client:addToCart', addToCart);
    socket.on('client:deleteToCart', deleteToCart);
} 

export default registerCartsHandler;