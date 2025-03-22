import User from "../models/user.model.js"
import bcrypt from "bcryptjs"
import { generateToken } from "../lib/utils.js";
import cloudinary from "../lib/cloudinary.js";

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

export const login = async (req,res) => {
    //res.send("Login route");
      const { email, password } = req.body;
    try {
      //try to find an account with given email and password
      const user = await User.findOne({email});

      if(!user){
      
        return res.status(400).json({message: "Invalid credentials"})
      }
      //If it passes the user name check then check the password

      const isPasswordCorrect = await bcrypt.compare(password, user.password);
      if(!isPasswordCorrect){
        
        return res.status(400).json({ message: "Invalid credentials"});
      }

      generateToken(user._id,res);

      res.status(200).json({
        _id:user._id,
        fullName: user.fullName,
        email: user.email,
        profilePic : user.profilePic,
      });

    } catch (error) {
      console.log("Error in login controller", error.message);
      res.status(500).json({ message: "Internal Server Error"});
    }

};

export const logout = (req, res) => {
    //res.send("Logout route");
    //If the user logs out, clear the cookie

    try {
      res.cookie("jwt", "", { maxAge: 0});
      res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
      console.log("Error in logout controller", error.message);
      res.status(500).json({ message: "Internal Server Error"});
    }
};

// Endpoint for profile modifications

export const updateProfile = async(req, res)=> {

  try {
    
    const {profilePic} = req.body;
    const userId = req.user._id;

    if(!profilePic){
      return res.status(400).json({ message: "Profile pic is required"});
    }

    const uploadResponse = await cloudinary.uploader.upload(profilePic)
    const updatedUser = await User.findByIdAndUpdate(userId, {profilePic:uploadResponse.secure_url}, {new:true});
    res.status(200).json(updatedUser);

  } catch (error) {
    console.log("Error in profile update: ", error);
    res.status(500).json({ message: "Internal server error"});

  }


};

export const checkAuth = (req, res) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    console.log("Error in checkAuth controller", error.message);
    res.status(500).json({ message: "Internal Server Error"});
    
  }
}