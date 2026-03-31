require("dotenv").config()
const express = require("express")
const app = express()
const PORT = process.env.PORT
const SECRET_KEY = process.env.SECRET_KEY
const ADMIN_MAIL = process.env.ADMIN_MAIL
const LOCAL_PASS = process.env.LOCAL_PASS
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const nodemailer = require("nodemailer")
const http = require("http")
const path = require("path")
const supabase = require("./database/db")
const cookieParser = require("cookie-parser")
const STRIPE_API_KEY = process.env.STRIPE_API_KEY
const {Stripe} = require("stripe")
const stripe = new Stripe(STRIPE_API_KEY)


// Middlewares
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.set("view engine","ejs")
app.use(express.static(path.join(__dirname,"public")))
app.use(cookieParser())


// Nodemailer Configuration 

const transporter = nodemailer.createTransport({
    service:"gmail",
    port:465,
    secure:true,
    auth:{
        user:ADMIN_MAIL,
        pass:LOCAL_PASS
    }
})


// Routes
app.get("/",(req,res)=>{
    res.send("Hello World")
})

app.get("/signup",(req,res)=>{
    res.render("signup")
})

app.post("/signup",async(req,res)=>{
    let {username,email,password} = req.body
    try{
        if(!username || !email || !password){
            return res.status(400).send("All fields are required")
        }
        let {data:users} = await supabase
            .from("users1")
            .select("*")
            .eq("email",email)
            .limit(1)
        
        if(users && users.length > 0){
            return res.status(409).send("Email already registered")
        }
        
        // Format date
        let today = new Date()
        let date = String(today.getDate()).padStart(2,"0")
        let month = String(today.getMonth()+1).padStart(2,"0")
        let year = today.getFullYear()
        today = date + "/" + month + "/" + year
        
        let salt = await bcrypt.genSalt(12)
        let hashedpassword = await bcrypt.hash(password,salt)
    

        let {data:newuser, error} = await supabase
            .from("users1")
            .insert([{
                username:username,
                email:email,
                password:hashedpassword,
                date:today
            }])
        
        if(error){
            return res.status(500).send("Signup failed: " + error.message)
        }
        
        return res.status(201).redirect("/signin")
    }
    catch(err){
        console.error("Signup error:", err)
        return res.status(500).send("Internal server error")
    }
})

app.get("/signin",(req,res)=>{
    res.render("signin")
})

app.post("/signin",async(req,res)=>{
    let {email,password} = req.body
    try{
        if(!email || !password){
            return res.status(400).send("All Fields are required")
        }
        let {data:users} = await supabase
            .from("users1")
            .select("*")
            .eq("email",email)
            .limit(1)
        
        if(!users || users.length === 0){
            return res.status(401).send("Invalid email or password")
        }
        
        let user = users[0]
        let comparedpassword = await bcrypt.compare(password,user.password)
        if(!comparedpassword){
            return res.status(401).send("Invalid email or password")
        }
        
        let token = jwt.sign({email},SECRET_KEY)
        res.cookie("token",token)
        return res.redirect("/profile")
    }
    catch(err){
        console.error("Signin error:", err)
        return res.status(500).send("Internal Server Error")
    }
})

// secure Middleware

const IsSignedIn = async(req,res,next) => {
    const token = req.cookies.token
    try{
        if(!token){
            return res.status(409).redirect("/signin")
        }
        else{
            let data = await jwt.verify(token,SECRET_KEY)
            req.user = data
            next()
        }
    }
    catch(err){
        return res.status(500).redirect("/signin")
    }
}

app.get("/profile",IsSignedIn,async(req,res)=>{
    try{
        let {data:users} = await supabase
            .from("users1")
            .select("*")
            .eq("email",req.user.email)
            .limit(1)
        
        if(!users || users.length === 0){
            return res.status(404).send("User not found")
        }
        
        let user = users[0]
        let username = user.username
        let email = user.email
        let date = user.date
        res.render("profile",{email,username,date})
    }
    catch(err){
        console.error("Profile error:", err)
        return res.status(500).send("Internal Server Error")
    }
})

app.get("/signout",(req,res)=>{
    res.cookie("token","")
    return res.redirect("/signin")
})

app.get("/forgot",(req,res)=>{
    res.render("forgot")
})

app.post("/forgot",async(req,res)=>{
    let {email} = req.body
    try{
        if(!email){
            return res.status(400).send("Email field required!")
        }
        let {data:users} = await supabase
            .from("users1")
            .select("email")
            .eq("email",email)
            .limit(1)
        
        if(!users || users.length === 0){
            return res.status(404).send("Email not found in system")
        }
        
        // TODO: Implement proper password reset with token-based link
        // For now, just send a notification email
        const sender = await transporter.sendMail({
            from:ADMIN_MAIL,
            to:email,
            subject:"E-Commerce | Password Reset Request",
            text:"Password Reset",
            html:`A password reset request was made for this email. If this wasn't you, please ignore this email.`
        })
        
        if(sender){
            return res.status(200).send("If email exists, you will receive reset instructions")
        }
    }
    catch(err){
        console.error("Forgot error:", err)
        return res.status(500).send("Internal Server Error")
    }
})

app.get("/products",IsSignedIn,async(req,res)=>{
    try{
        let {data:users} = await supabase
            .from("users1")
            .select("*")
            .eq("email",req.user.email)
            .limit(1)
        
        if(!users || users.length === 0){
            return res.status(404).send("User not found")
        }
        
        let username = users[0].username
        res.render("products",{username})
    }
    catch(err){
        console.error("Products error:", err)
        return res.status(500).send("Internal Server Error")
    }
})

app.get("/buy/:price/:item",IsSignedIn,async(req,res)=>{
    let price = req.params.price
    let item = req.params.item
    try{
        if(!price || isNaN(parseInt(price)) || parseInt(price) <= 0){
            return res.status(400).send("Invalid price")
        }
        
        // Stripe minimum: ~50 cents (~₹42), so require minimum ₹50
        if(parseInt(price) < 50){
            return res.status(400).send("Minimum price is ₹50 (approximately $0.60). You entered ₹" + price)
        }
        
        if(!item){
            return res.status(400).send("Item name is required")
        }
        
        const session = await stripe.checkout.sessions.create({
            payment_method_types:["card"],
            mode:"payment",
            line_items: [
                {
                    price_data: {
                        currency: "inr",
                        unit_amount: parseInt(price) * 100,
                        product_data: {
                            name: item
                        }
                    },
                    quantity: 1
                }
            ],
            success_url: `http://localhost:${PORT}/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `http://localhost:${PORT}/products`
        })
        
        if(!session || !session.url){
            return res.status(500).send("Failed to create Stripe session")
        }
        
        return res.redirect(303, session.url)
    }
    catch(err){
        console.error("Stripe session error:", err.message)
        return res.status(500).send("Payment error: " + err.message)
    }
})

app.get("/cart/:price/:item",IsSignedIn,async(req,res)=>{
    let price = req.params.price
    let item = req.params.item
 try{
        if(!price || isNaN(parseInt(price)) || parseInt(price) <= 0){
            return res.status(400).send("Invalid price")
        }
        
        // Stripe minimum: ~50 cents (~₹42), so require minimum ₹50
        if(parseInt(price) < 50){
            return res.status(400).send("Minimum price is ₹50 (approximately $0.60). You entered ₹" + price)
        }
        
        if(!item){
            return res.status(400).send("Item name is required")
        }
        
        const session = await stripe.checkout.sessions.create({
            payment_method_types:["card"],
            mode:"payment",
            line_items: [
                {
                    price_data: {
                        currency: "inr",
                        unit_amount: parseInt(price) * 100,
                        product_data: {
                            name: item
                        }
                    },
                    quantity: 1
                }
            ],
            success_url: `http://localhost:${PORT}/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `http://localhost:${PORT}/products`
        })
        
        if(!session || !session.url){
            return res.status(500).send("Failed to create Stripe session")
        }
        
        return res.redirect(303, session.url)
    }
    catch(err){
        console.error("Stripe session error:", err.message)
        return res.status(500).send("Payment error: " + err.message)
    }
})

app.get("/success",IsSignedIn,async(req,res)=>{
    const sessionId = req.query.session_id
    try{
        if(!sessionId){
            return res.status(400).send("No session ID provided")
        }
        
        const session = await stripe.checkout.sessions.retrieve(sessionId)
        
        if(session.payment_status === "paid"){
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Payment Successful</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .success { color: green; font-size: 24px; }
                        a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: blue; color: white; text-decoration: none; border-radius: 5px; }
                    </style>
                </head>
                <body>
                    <div class="success">✓ Payment Successful!</div>
                    <p>Thank you for your purchase.</p>
                    <a href="/products">Continue Shopping</a>
                </body>
                </html>
            `)
        }
        else{
            return res.status(400).send("Payment not completed")
        }
    }
    catch(err){
        console.error("Success route error:", err)
        return res.status(500).send("Error retrieving payment status")
    }
})

app.listen(PORT,()=>{
    console.log(`Server is running at PORT ${PORT}`)
})