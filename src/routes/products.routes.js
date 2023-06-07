import { Router } from 'express';
import ProductsManager from '../dao/mongo/Managers/products.js';

const productsRouter = Router();

const productsService = new ProductsManager();

productsRouter.get('/', async (req, res) => {

    const limit = parseInt(req.query.limit) || 10;
    const page = parseInt(req.query.page) || 1;
    const sort = req.query.sort === 'desc' ? -1 : 1;
    const query = req.query.query || '';
    
  try {
    const result = await productsService.getProductsPage(limit, page, query, sort);
    
    const totalPages = result.totalPages;
    const prevPage = result.hasPrevPage ? page - 1 : null;
    const nextPage = result.hasNextPage ? page + 1 : null;
    const hasPrevPage = result.hasPrevPage;
    const hasNextPage = result.hasNextPage;
    const prevLink = result.hasPrevPage ? `/products/?limit=${limit}&page=${prevPage}&sort=${sort}&query=${query}` : null;
    const nextLink = result.hasNextPage ? `/products/?limit=${limit}&page=${nextPage}&sort=${sort}&query=${query}` : null;

    res.json({
        status: 'success',
        payload: result.docs,
        totalPages,
        prevPage,
        nextPage,
        page,
        hasPrevPage,
        hasNextPage,
        prevLink,
        nextLink
      });
    } catch (error) {
      res.status(500).json({ status: 'error', message: error.message});
    }

});

productsRouter.get('/:pid', async(req, res) => {
    const { pid } = req.params;
    const product = await productsService.getProductById({_id: pid});
    if(!product) return res.status(404).send({ status: 'error', error: 'Product not found' });
    res.send({ status: 'success', payload: product });
});


productsRouter.post('/', async(req, res) => {
    const { title, description, code,price, stock, category, thumbnail } = req.body;

    if(!title|| !description|| !code|| !price ||!stock ||!category) return res.status(400).send({ status: 'error', error: "Incomplete values" });

    const duplicate = await productsService.findByCode(code)

    if(duplicate){
        return res.status(400).send({ status: 'error', error: "Duplicated Code" });
    } else {
        const product = {
            title, 
            description, 
            code,
            price, 
            stock, 
            category, 
            thumbnail
        }
        const result = await productsService.createProduct(product);
        res.sendStatus(201);
    }  
  
})

productsRouter.put('/:pid', async(req, res) => {
    const {pid} = req.params;
    const updatedProduct = req.body;
    const result = await productsService.updateProduct(pid, updatedProduct);
    res.sendStatus(201);
})

productsRouter.delete('/:pid', async(req, res) => {
    const {pid} = req.params;
    await productsService.deleteProduct(pid);
    res.sendStatus(200);

})


export default productsRouter;