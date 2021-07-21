const {Router} = require('express')
const bcrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

router.post(
    '/register',
    [
        check('email', 'invalid email').isEmail(),
        check('password', 'min length 6 symbols').isLength({min: 6})
    ], 
    async (req,res) => {
    try {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'invalid register data'
            })
        }


        const {email, password} = req.body
    
        const candidate = await User.findOne({email})
        if(candidate) {
            return res.status(400).json({message:'this user already exists'})
    }
        const hashedPassword = await bcrypt.hash(password,12)
        const user = new User({email, password: hashedPassword})
        await user.save()
    res.status(201).json({message:'user create'})

    } catch(e) {
        res.status(500).json({message: 'что то пошло не так пробуйте снова'})
    }
})

router.post(
    '/login', 
    [
        check('email', 'Enter correct email').normalizeEmail().isEmail(),
        check('password', 'enter password').exists()
    ],
    async (req,res) => {
        try {
            const errors = validationResult(req)
    
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'invalid auth data'
                })
            }

            const {email, password} = req.body
            const user = await User.findOne({email})
            if(!user) {
                return res.status(400).json({message:'User not find'})
            }
            const isMatch = await bcrypt.compare(password, user.password)
            if(!isMatch) {
                return res.status(400).json({message: 'wrong password, try again'})
            }

            const token = jwt.sign(
                { userId: user.Id },
                config.get('jwtSecret'),
                { expiresIn: '1h' }
            )
            res.json({token, userId: user.id})
            

        } catch(e) {
            res.status(500).json({message: 'что то пошло не так пробуйте снова'})
        }
})

module.exports = router