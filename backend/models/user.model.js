import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userScehma = new mongoose.Schema({
    name: {
        type:String,
        reuired:true
    },
    email: {
        type: String,
        required: [true,"email is required"],
        unique:true,
        lowercase:true
    },
    password: {
        type:String,
        required:true,
        minlength:[6, "password must be 6 characters long"]
    },
    cartItems: [
        {
            quantity: {
                type:Number,
                default:1
            },
            product: {
                type: mongoose.Schema.Types.ObjectId,
                ref:"Product"
            }
        }
    ],
    role: {
        type: String,
        enum:["customer","admin"],
        default: "customer"
    }
},
{timestamps:true})

//presave hook to hash password before saving to database
userScehma.pre("save",async function (next){
    if(!this.isModified("password")) return next()
    
    try {
        const salt=await bcrypt.genSalt(10)
        this.password=await bcrypt.hash(this.password,salt)
        next()
    } catch(error) {
        next(error)
    }
})
userScehma.methods.comparePassword = async function (password) {
    return bcrypt.compare(password,this.password)
}

const User = mongoose.model("User",userScehma)
export default User