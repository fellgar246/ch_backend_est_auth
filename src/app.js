import express from 'express';
import morgan from 'morgan';
import handlebars from 'express-handlebars';
import mongoose from 'mongoose';
import MongoStore from 'connect-mongo';
import { Server } from 'socket.io';
import session from 'express-session';
import passport from 'passport';
import 'dotenv/config';

import productsRouter from './routes/products.routes.js';
import cartsRouter from './routes/carts.routes.js';
import viewsRouter from './routes/views.routes.js';
import sessionsRouter from './routes/session.routes.js';

import registerChatHandler from "./listeners/chatHandler.js";
import registerProductsHandler from './listeners/productsHandler.js';
import registerCartsHandler from './listeners/cartsHandler.js';;
import initializePassport from './config/passport.config.js';
import __dirname from './utils.js';

const app = express();
const PORT = process.env.PORT || 8080; 
const server = app.listen(PORT, () => console.log(`listening on PORT ${PORT}`));
const io = new Server(server);
const connection = mongoose.connect(`mongodb+srv://root:${process.env.MONGO_KEY}@cluster0.lcae78w.mongodb.net/ecommerce?retryWrites=true&w=majority`)

app.engine('handlebars', handlebars.engine());
app.set('views', `${__dirname}/views`);
app.set('view engine', 'handlebars');

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(`${__dirname}/public`));
app.use(session({
    store: new MongoStore({
        mongoUrl: `mongodb+srv://root:${process.env.MONGO_KEY}@cluster0.lcae78w.mongodb.net/ecommerce?retryWrites=true&w=majority`,
        ttl: 3600,
    }),
    secret:"CoderS3cret",
    resave:false,
    saveUninitialized:false
}))
app.use(passport.initialize());
initializePassport();
app.use(morgan("dev"));

app.use('/', viewsRouter);
app.use('/api/products', productsRouter);
app.use('/api/carts', cartsRouter);
app.use('/api/sessions', sessionsRouter)

io.on('connection', socket=> {
    console.log("Cliente conectado");
    registerChatHandler(io, socket);
    registerProductsHandler(io,socket);
    registerCartsHandler(io,socket);
})





