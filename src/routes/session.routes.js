import { Router } from "express";
import userModel from "../dao/mongo/models/user.js";
import passport from "passport";


const sessionsRouter = Router();

sessionsRouter.post('/register', passport.authenticate('register', {failureFlash:'/api/sessions/registerFail'}),async(req,res)=>{
    res.send({status:"success",message:"Registered"});
})

sessionsRouter.get('/registerFail', (req, res) => {
    console.log(req.session.messages);
    res.status(400).send({status:"error", error:req.session.messages});
})

sessionsRouter.post('/login',passport.authenticate('login', {failureFlash:'/api/sessions/loginFail'}),async(req,res)=>{

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


export default sessionsRouter;