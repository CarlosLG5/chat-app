import User from "../models/user.model.js"
import bcrypt from "bcryptjs"
import { generateToken } from "../lib/utils.js";

export const signup = async (req, res) => {
    //res.send("Signup route"); test
    const {fullName, email, password} = req.body
    try {
        //Checking for all fields to be filled
      if(!fullName || !email || !password){
        return res.status(400).json({ message: "All fields are required"});
      }
        //Checking for password length
      if(password.length < 6){
            return res.status(400).json({ message: "Password must be at least 6 characters" });
        }
        //Checking for email in database
      const user = await User.findOne({email})
      if (user) return res.status(400).json({ message: "Email already exists" });

    
        //Hashing the password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    const newUser = new User({
        fullName,
        email,
        password: hashedPassword
    })

    if(newUser){
        //Generate jwt token
        generateToken(newUser._id, res)
        await newUser.save();

        res.status(201).json({
            _id: newUser._id,
            fullName: newUser.fullName,
            email: newUser.email,
            profilePic: newUser.profilePic,
        })
    }else{
        res.status(400).json({ message: "Invalid user data"});
    }

    } catch (error) {
      console.log("Error in signup controller", error.message);
      res.status(500).json({ message: "Internal Server Error"})
    }
};

export const login = (req,res) => {
    res.send("Login route");
};

export const logout = (req, res) => {
    res.send("Logout route");
};