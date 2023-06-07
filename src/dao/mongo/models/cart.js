import mongoose from 'mongoose';

const collection = "Carts";

const schema = new mongoose.Schema({
        products: { 
            type: [
            {
                product: {
                    type:mongoose.SchemaTypes.ObjectId,
                    ref:'Products'
                },
                quantity: {
                    type: Number
                }
            }
        ],
        default: []
    }
})

schema.pre('find',function(){
    this.populate('products.product');
})

schema.pre('findOne',function(){
    this.populate('products.product');
})

const cartModel = mongoose.model(collection,schema);

export default cartModel;