import cartModel from "../models/cart.js";
import mongoose from "mongoose";

export default class cartsManager {
    
    getCarts = () =>{
        return cartModel.find();
    }

    getCartById = (params) =>{
        return cartModel.findOne(params).lean();
    }

    postCart = (products) =>{
        return cartModel.create({products});
    }

    postCartProduct = (cid, pid, quantity) =>{
        return cartModel.updateOne(
            {_id: cid}, 
            {$push: {
                products: {product: new mongoose.Types.ObjectId(pid), quantity: quantity},
            }}
        );
    }

    deleleProdByCart = (cid, pid) => {
        return cartModel.findOneAndUpdate(
            { _id: cid },
            { $pull: { products: { product: pid } } },
            { new: true }
          );
    }

    updateAllCart = (cid, products) => {
        return cartModel.findOneAndUpdate(
            { _id: cid },
            { products: products },
            { new: true } 
        );
    }

    updateQuantity = (cid, pid, quantity) => {
        return cartModel.findOneAndUpdate(
            { _id: cid, "products.product": pid },
            { $set: { "products.$.quantity": quantity } },
            { new: true }
          );
    }

    deleteAllProd = (cid) => {
       return cartModel.findOneAndUpdate(
            { _id: cid },
            { products: [] },
            { new: true }
        )
    }



}