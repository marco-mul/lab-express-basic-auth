const router = require("express").Router();
const mongoose = require("mongoose");
const session = require("express-session");

const bcryptjs = require("bcryptjs");
const User = require('../models/User.model')

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

// GET sign up page

router.get('/sign-up', (req, res) => {
  res.render('sign-up')
})

// POST sign up page

router.post('/sign-up', async (req, res, next) => {
  const { username, password } = req.body
  if (!username) {
    return res.status(400).render('sign-up', {
      errorMessage: 'Please provide your username.',
    })
  }

  if (password.length < 8) {
    return res.status(400).render('sign-up', {
      errorMessage: 'Your password needs to be at least 8 characters long.',
    })
  }

  User.findOne({ username }).then((found) => {
    if (found) {
      return res
        .status(400)
        .render('sign-up', { errorMessage: 'Username already taken.' })
    }

    return bcryptjs
      .genSalt(10)
      .then((salt) => bcryptjs.hash(password, salt))
      .then((hashedPassword) => {
        return User.create({
          username,
          password: hashedPassword,
        })
      })
      .then((user) => {
        console.log(req.session)
        req.session.user = user
        res.redirect('/')
      })
      .catch((error) => {
        if (error instanceof mongoose.Error.ValidationError) {
          return res
            .status(400)
            .render('sign-up', { errorMessage: error.message })
        }
        if (error.code === 11000) {
          return res.status(400).render('sign-up', {
            errorMessage:
              'The username you chose is already taken.',
          })
        }
        return res
          .status(500)
          .render('sign-up', { errorMessage: error.message })
      })
  })

})

// check if user is logged out or in

const isLoggedOut = (req, res, next) => {
  if (!req.session.user) {

    return res.redirect('sign-in')
  }
  req.user = req.session.user
  next()
}

const isLoggedIn = (req, res, next) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  next();
};





// GET log in page

router.get("/sign-in", (req, res, next) => {
  res.render("sign-in");
});

// POST log in page
router.post('/sign-in', isLoggedOut, (req, res, next) => {
  const { username, password } = req.body

  if (!username) {
    return res.status(400).render('sign-in', {
      errorMessage: 'Please provide your username.',
    })
  }

  if (password.length < 8) {
    return res.status(400).render('sign-in', {
      errorMessage: 'Your password needs to be at least 8 characters long.',
    })
  }

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        return res.status(400).render('sign-in', {
          errorMessage: 'Wrong credentials.',
        })
      }

      bcryptjs.compare(password, user.password).then((isSamePassword) => {
        if (!isSamePassword) {
          return res.status(400).render('sign-in', {
            errorMessage: 'Wrong credentials.',
          })
        }
        req.session.user = user
        return res.render('success')
      })
    })

    .catch((err) => {
      next(err)
      return res.status(500).render("sign-in", { errorMessage: err.message });
    })
})

router.get("/main", (req, res, next) => {
  if (req.session.user) {
    res.render("main");
  } else {
    res.redirect('/sign-in');;
  }
});

router.get("/private", (req, res, next) => {
  if (req.session.user) {
    res.render("private");
  } else {
    res.redirect('/sign-in');;
  }
});


module.exports = router;
