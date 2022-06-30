import bcrypt from "bcrypt"

const plainPW = "12345"

const numberOfRounds = 12

console.log(`The algorithm will be calculated 2^${numberOfRounds} times --> ${Math.pow(2, numberOfRounds)} times!!`)

console.time("hashing")
const hash = bcrypt.hashSync(plainPW, numberOfRounds) // instead of hashing directly "1234" only, they are "salting" the hash by doing hash(".3fWrNXq7ebUBoNq0N1K9u"+ "1234")
console.timeEnd("hashing")

console.log("HASH: ", hash)

const isOk = bcrypt.compareSync(plainPW, hash)

console.log("Do they match? ", isOk)
