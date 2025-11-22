import User from "../models/user.model.js"
import { redis } from "../lib/redis.js"
import jwt from "jsonwebtoken"

const generateToken = (userId) => {
    const accessToken  = jwt.sign({userId},process.env.ACCESS_TOKEN_SECRET,{
        expiresIn: "15m",
    })
    const refreshToken = jwt.sign({userId}, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "7d",
    })
    return { accessToken, refreshToken }
} 

const storeRefreshToken = async (userId,refreshToken) => {
    await redis.set(`refresh_token:${userId}`,refreshToken,"EX",7*24*60*60)
}

const setCookies = (res,accessToken,refreshToken) => {

    res.cookie("accessToken",accessToken, {
        httpOnly:true, //prevents XSS attacks
        secure: process.env.NODE_ENV === "production",
        sameSite:  "strict", //prevents CSRF attacks
        maxAge: 15*60*1000

    })

    res.cookie("refreshToken",refreshToken, {
        httpOnly:true, //prevents XSS attacks
        secure: process.env.NODE_ENV === "production",
        sameSite:  "strict", //prevents CSRF attacks
        maxAge: 7*24*60*60*1000

    })
}

export async function signup(req,res) {
    const {email, password, name} =req.body
    try {
        const userExists = await User.findOne({email})
        if(userExists) {
            return res.status(400).json({message: "User already exists"})
        }   
        const user = await User.create({name,email,password}) 
        const {accessToken,refreshToken}= generateToken(user._id)
        await storeRefreshToken(user._id,refreshToken)
        setCookies(res,accessToken,refreshToken)

        res.status(201).json({user: {
            _id:user._id,
            name:user.name,
            email:user.email,
            role:user.role
        },message: "User created successfully"})
    } catch(error) { 
        console.log("Error in signup controller ", error.message)
        res.status(500).json({message: "Internal server error"})
    }
}

export async function login(req,res) {
    try {
        const {email,password} = req.body
        const user = await User.findOne({email})
        if(!user) {
            console.log("Wrong email")
            return res.status(400).json({message: "Incorrect credentials"})
        }
        const isPasswordCorrect = await user.comparePassword(password)
        if(user && isPasswordCorrect) {
            const {accessToken, refreshToken} = generateToken(user._id)
            await storeRefreshToken(user._id,refreshToken)
            setCookies(res,accessToken,refreshToken)

            res.status(200).json({user: {
                _id:user._id,
                name:user.name,
                email:user.email,
                role:user.role
            },message: "Logged in successfully" })
        }

        if(!isPasswordCorrect) {
            console.log("Wrong password")
            return res.status(400).json({message: "Incorrect credentials"})
        }
    } catch(error) {
        console.log("Error in login controller ", error.message)
        res.status(500).json({message: "Internal server error"})
    }
}

export async function logout(req, res) {
    try {
        const refreshToken= req.cookies.refreshToken
        if(refreshToken) {
            const decoded = jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET)
            await redis.del(`refresh_token:${decoded.userId}`)
        }
        res.clearCookie("accessToken")
        res.clearCookie("refreshToken")
        res.status(200).json({message: "Logged out successfully"})
    } catch(error) {
        console.log("Error in logout controller ", error.message)
        res.status(500).json({message: "Internal server error"})
    }
}

export async function refreshToken(req,res) {
    try {
        const refreshToken = req.cookies.refreshToken

        if(!refreshToken) {
            return res.status(401).json({message: "No token found"})
        }

        const decoded = jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET)
        const storedToken = await redis.get(`refresh_token:${decoded.userId}`)

        if(storedToken !== refreshToken) {
            return res.status(401).json({message: "Invalid token"})
        }
        const accessToken = jwt.sign(
            {userId:decoded.userId},
            process.env.REFRESH_TOKEN_SECRET,
            {expiresIn: "15m"})

        res.cookie("accessToken",accessToken, {
            httpOnly:true, //prevents XSS attacks
            secure: process.env.NODE_ENV === "production",
            sameSite:  "strict", //prevents CSRF attacks
            maxAge: 15*60*1000
        })
        res.json({message: "Token refreshed successfully"})
    } catch(error) {
        console.log("Error in refresh token controller ", error.message)
        res.status(500).json({message: "Internal server error"})
    }
}