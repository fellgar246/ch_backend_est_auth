import { Router } from 'express';
import cartsManager from '../dao/mongo/Managers/carts.js';

const cartsRouter = Router();

const cartService = new cartsManager();

cartsRouter.post("/", async(req, res) => {
    const { products } = req.body;
    const result = await cartService.postCart(products);
    res.sendStatus(201);
})

cartsRouter.get("/:cid", async(req, res) => {
    const {cid} = req.params;  
    const cart = await cartService.getCartById({_id: cid});
    if(!cart) return res.status(404).send({ status: 'error', error: 'Cart not found' });
    res.send({ status: 'success', payload: cart });
})

cartsRouter.get("/", async(req, res) => {
    const carts = await cartService.getCarts();
    res.send({ status: 'success', payload: carts });
})

cartsRouter.post("/:cid/products/:pid", async(req,res) => {
    const {cid, pid} = req.params;
    const { quantity } = req.body
    const result = await cartService.postCartProduct(cid, pid, quantity);
    res.send({ status: 'success', payload: result });;
})

cartsRouter.delete("/:cid/products/:pid", async(req, res) => {
    const {cid, pid} = req.params; 
    const result = await cartService.deleleProdByCart(cid, pid)
    res.send({ status: 'success', payload: result });
})

cartsRouter.put("/:cid", async(req, res) => {
    const {cid } = req.params;
    const { products }  = req.body
    const result = await cartService.updateAllCart(cid, products);
    res.sendStatus(200);
})

cartsRouter.put("/:cid/products/:pid", async(req, res) => { 
    const { cid, pid } = req.params;
    const  { quantity } = req.body

    const result = await cartService.updateQuantity(cid, pid, quantity)
    res.sendStatus(200);
})

cartsRouter.delete("/:cid", async(req, res) => {
    const { cid } = req.params;
    const result = await cartService.deleteAllProd(cid)
    res.sendStatus(200);
})


export default cartsRouter;