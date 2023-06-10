import { Router } from 'express';
import { privacy } from '../middlewares/auth.js';
import ProductsManager from '../dao/mongo/Managers/products.js';
import productModel from '../dao/mongo/models/product.js';
import cartsManager from '../dao/mongo/Managers/carts.js';

const viewsRouter = Router();

const productService = new ProductsManager();
const cartService = new cartsManager();

viewsRouter.get('/', async (req, res) => {
    const result = await productModel.find().lean();
    res.render('home',{products: result})
});
viewsRouter.get('/realtimeproducts', (req, res) => {
    res.render('realTimeProducts')
});

viewsRouter.get('/chat',async(req,res)=>{
    res.render('chat');
})

viewsRouter.get('/products',privacy('PRIVATE'),async(req,res)=>{
    const { page = 1 } = req.query;
    const limit = 10;
    const { docs, hasPrevPage, hasNextPage, prevPage, nextPage, ...rest} = await productService.getProducts( limit, page );
    res.render('products',{ products: docs, page: rest.page, hasPrevPage, hasNextPage, prevPage, nextPage, user: req.session.user });
})

viewsRouter.get('/carts/:cid',async(req,res)=>{
    const { cid } = req.params
    const cart = await cartService.getCartById({_id: `${cid}`})
    res.render('carts', { products: cart.products, id: cart._id });
})

viewsRouter.get('/register',privacy('NO_AUTHENTICATED'),async(req,res)=>{
    res.render('register');
})

viewsRouter.get('/login',privacy('NO_AUTHENTICATED'),(req,res)=>{
    res.render('login')
})

viewsRouter.get('/restorePassword',privacy('NO_AUTHENTICATED'), (req,res)=> {
    res.render('restorePassword')
})

viewsRouter.get('/jwtProfile', (req,res) => {
    res.render('jwtProfile')
})


export default viewsRouter;