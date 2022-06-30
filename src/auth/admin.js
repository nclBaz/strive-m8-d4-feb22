import createHttpError from "http-errors"

export const adminOnlyMiddleware = (req, res, next) => {
  // This needs to be used AFTER the authentication middleware. It has only one job: checking the role of the current user

  if (req.user.role === "Admin") {
    next()
  } else {
    next(createHttpError(403, "Admin only endpoint!"))
  }
}
