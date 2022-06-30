import jwt from "jsonwebtoken"

const token = jwt.sign({ _id: "12j3o1j2o3j21io3jo", role: "User" }, "mysup3rs3cr3tpw", { expiresIn: "1 week" }) // jwt.sign(payload, secret, options)
console.log("TOKEN: ", token)

const payload = jwt.verify(token, "mysup3rs3cr3tpw") // jwt.verify(token, secret)

console.log("PAYLOAD: ", payload)

// jwt.sign({ _id: "12j3o1j2o3j21io3jo", role: "User" }, "mysup3rs3cr3tpw", { expiresIn: "1 week" }, (err, token) => {
//   if(err) console.log(err)
//   else console.log(token)
// })

const generateAccessToken = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, "mysup3rs3cr3tpw", { expiresIn: "1 week" }, (err, token) => {
      if (err) reject(err)
      else resolve(token)
    })
  ) // input PAYLOAD --> output PROMISE(TOKEN)

/* USAGES

generateAccessToken({ _id: "12j3o1j2o3j21io3jo", role: "User" }).then( token => console.log(token)).catch(err => console.log(err))

try{
  const token = await generateAccessToken({ _id: "12j3o1j2o3j21io3jo", role: "User" })
} catch(err){
  console.log(err)
}
*/

const verifyAccessToken = token =>
  new Promise((res, rej) =>
    jwt.verify(token, "mysup3rs3cr3tpw", (err, payload) => {
      if (err) rej(err)
      else res(payload)
    })
  )

// const payload2 = await verifyAccessToken("")
