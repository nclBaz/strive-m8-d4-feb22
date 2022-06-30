import createHttpError from "http-errors"
import { verifyAccessToken } from "./tools.js"

export const JWTAuthMiddleware = async (req, res, next) => {
  // 1. Check if authorization header is in the request, if it is not --> 401
  if (!req.headers.authorization) {
    next(createHttpError(401, "Please provide Bearer Token in the authorization header!"))
  } else {
    try {
      // 2. If authorization header is there we can extract the token from it (Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MmJhYzg1NmRkMzM5YTBmNzU2OGVhNjEiLCJyb2xlIjoiQWRtaW4iLCJpYXQiOjE2NTY0OTI5MTMsImV4cCI6MTY1NzA5NzcxM30.VdPVmNkUGOvSf4y39rMuXPI_aaafxexqU65Q2Jgbefo")
      const token = req.headers.authorization.replace("Bearer ", "")

      // 3. Verify token (check the expiration date and check the signature integrity), if everything is fine we should get back the payload ({_id, role})
      const payload = await verifyAccessToken(token)

      // 4. If token is ok --> next

      req.user = {
        _id: payload._id,
        role: payload.role,
      }

      next()
    } catch (error) {
      // 5. If the token is not ok --> jsonwebtoken library should throw some errors, so we gonna catch'em and --> 401
      console.log(error)
      next(createHttpError(401, "Token not valid!"))
    }
  }
}
