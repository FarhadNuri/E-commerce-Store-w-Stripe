import mongoose from "mongoose"

export async function connectDB() {
    try {
        const cnct = await mongoose.connect(process.env.MONGO_URI)
        console.log(`MongoDB conncected ${cnct.connection.host}`)
    } catch(error) {
        console.log("Error connecting to MongoDB", error.message)
    }
}