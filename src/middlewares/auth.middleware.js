import jwt from "jsonwebtoken";
import {User} from "../models/user.models.js"
import {ErrorResponse} from "../utils/ErrorResponse.js"
import {asyncHandler} from "../utils/asyncHandler.js"

export const verifyJWT=asyncHandler(async (req,_ , next)=>{
    const token=req.cookies.accessToken || req.body.acessToken || req.header("Authorization")?.replace("Bearer ","")

    if(!token){
        throw new ErrorResponse(401,"unauthorized");
    }
    try {
        const decodedToken=jwt.verify(token,process.env.REFRESH_TOKEN_SECRET)
        const user=await User.findById(decodedToken?._id).select("-refreshToken -password")
        if(!user){
            throw new ErrorResponse(401,"unauthorized")
        }
        req.user=user
        next()
    } catch (error) {
        throw new ErrorResponse(401,error?.message ||"unauthorized")
    }

})