import { Router } from "express";
import userModel from "../dao/mongo/models/user.js";
import passport from "passport";
import { validatePassword, createHash } from "../utils.js";


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
    req.session.destroy((err) => {
        if (err) {
          console.error('Error al destruir la sesión:', err);
        } else {
          res.clearCookie('connect.sid');
        }
      });   
    res.send({status:"success",message:"Logout"});
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


export default sessionsRouter;