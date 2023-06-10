import { Router } from "express";
import userModel from "../dao/mongo/models/user.js";
import passport from "passport";
import { validatePassword, createHash, generateToken } from "../utils.js";
import { authToken } from "../middlewares/jwtAuth.js";


const sessionsRouter = Router();

sessionsRouter.post('/register', passport.authenticate('register', {failureFlash:'/api/sessions/registerFail', failureMessage:true}),async(req,res)=>{
    res.send({status:"success",message:"Registered"});
})

sessionsRouter.get('/registerFail', (req, res) => {
    console.log(req.session.messages);
    res.status(400).send({status:"error", error:req.session.messages});
})

sessionsRouter.post('/login',passport.authenticate('login', {failureFlash:'/api/sessions/loginFail', failureMessage:true}),async(req,res)=>{

    req.session.user = {
        name: req.user.name,
        role: req.user.role,
        id: req.user.id,
        email: req.user.email
    }
     
    res.send({status:"success",message:"Login"});
 
})

sessionsRouter.get('/loginFail', (req, res) => {
    console.log(req.session.messages);
    if(req.session.messages.length > 5) return res.status(400).send({message:"Demasiados intentos"});
    res.status(400).send({status:"error", error:req.session.messages});
})

sessionsRouter.get('/logout',async (req, res) => {
    if (req.session) {
        req.session.destroy();  
        res.clearCookie('connect.sid');
    }
    res.send({status:"success",message:"Logout"});
})

sessionsRouter.post('/jwtLogin', async(req, res) => {
    const {email, password} = req.body;

    let accessToken;
    if(email==="adminCoder@coder.com" && password==="adminCod3r123"){
        const user = {
            id:0,
            name: 'Admin',
            role: 'admin',
            email: 'adminCoder@coder.com'
        }
        accessToken = generateToken(user);
        res.send({status:"success", accessToken: accessToken});
    }

    let user;

    user = await userModel.findOne({email});
    if(!user) return res.sendStatus(400);

    const isValidPassword = await validatePassword(password, user.password);
    if(!isValidPassword) return res.sendStatus(400);

    user = {
        id: user._id,
        name: `${user.first_name} ${user.last_name}`,
        email:user.email,
        role:user.role
    }
    accessToken = generateToken(user);
    res.send({status:"success", accessToken: accessToken});
})

sessionsRouter.get('/jwtProfile', authToken, async(req,res) => {
    console.log(req.user);
    res.send({status: "success", payload:req.user})
})

sessionsRouter.post('/restorePassword', async(req,res) => {
    const {email, password} = req.body;
    //TODO: pasar al manager
    const user = await userModel.findOne({email});
    if(!user) return res.status(400).send({status:"error", error: "User doesn't exist"});
    
    const isSamePassword = await validatePassword(password, user.password);
    if(isSamePassword) return res.status(400).send({status:"error", error: "Cannot replace password with current password"})

    const newHashedPassword = await createHash(password);
    await userModel.updateOne({email},{$set:{password:newHashedPassword}});

    res.status(200).send({status:"success",message:"Password changed"});
})

sessionsRouter.get('/github',passport.authenticate('github'), (req, res) => {});

sessionsRouter.get('/githubcallback',passport.authenticate('github'), (req, res) => {
    const user = req.user;
    req.session.user = {
        id: user.id,
        name: user.first_name,
        role: user.role,
        email: user.email
    }
    res.send({status:"success", message:"Logueado con GITHUB"})
});


export default sessionsRouter;