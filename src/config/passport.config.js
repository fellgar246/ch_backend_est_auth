import passport from "passport";
import local from "passport-local";
import 'dotenv/config';
import GithubStrategy from 'passport-github2';
import userModel from "../dao/mongo/models/user.js";
import { createHash, validatePassword } from "../utils.js";

const LocalStrategy = local.Strategy;

const initializePassport = () => {
    passport.use('register', new LocalStrategy({passReqToCallback:true, usernameField: 'email'}, async(req, email, password, done) => {
        
        try {
            const {first_name, last_name } = req.body;

            const exists = await userModel.findOne({email});
            if(exists) return done(null,false,{message:'El usuario ya existe'});
    
            const hashedPassword = await createHash(password);
            const user = {
                first_name,
                last_name,
                email,
                password: hashedPassword
            }
    
            const result = await userModel.create(user);
            done(null,result);
        } catch (error) {
            done(error);
        }

    }));

    passport.use('login', new LocalStrategy({usernameField:'email'},async(email, password, done)=> {

        if(email==="adminCoder@coder.com" && password==="adminCod3r123"){
            const user = {
                id:0,
                name: 'Admin',
                role: 'admin',
                email: 'adminCoder@coder.com'
            }
            return done(null,user)
        }

        let user;
    
        user = await userModel.findOne({email});
        if(!user) return done(null,false,{message: "Credenciales incorrectas"})
    
        const isValidPassword = await validatePassword(password, user.password);
        if(!isValidPassword) return done(null,false,{message:"Contraseña inválida"})
    
        user = {
            id: user._id,
            name: `${user.first_name} ${user.last_name}`,
            email:user.email,
            role:user.role
        }

        return done(null, user);
    }));

    passport.use(
        'github', 
        new GithubStrategy(
            {
                clientID: `${process.env.GITHUB_ID}`,
                clientSecret: `${process.env.GITHUB_SECRET}`,
                callbackURL: "http://localhost:8080/api/sessions/githubcallback"
            },
            async(accessToken, refreshToken, profile, done) =>{
                try {
                    console.log(profile);
                    const {name, email, id} = profile._json;
                    let verifyEmail = email || `${id}@github.com`;
                    const user = await userModel.findOne({ email: verifyEmail });
                    if(!user) {
                        console.log("nuevo usuario");
                        const newUser = {
                            first_name: name,
                            email: email || `${id}@github.com`,
                            password: ''
                        }
                        const result = await userModel.create(newUser);
                        console.log("result", result);
                        return done(null,result)
                    }
                    return done(null, user)
                } catch (error) {
                    done(error);
                }
            }
        )
    );

    passport.serializeUser(function(user,done){
        return done(null, user.id);
    });
    passport.deserializeUser(async function(id,done){
        if(id===0){
            return done(null,{
                role:"admin",
                name:"ADMIN"
            })
        }
        const user = await userModel.findOne({_id: id});
        return done(null, user);
    });
}


export default initializePassport;