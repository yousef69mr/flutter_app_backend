import express from "express";
import * as dotenv from "dotenv";
import cors from "cors";
import jwt from "jsonwebtoken";
import { PrismaClient, UserRole } from '@prisma/client'
import fileUpload from 'express-fileupload';
import * as fs from 'fs';

const db = globalThis.prisma || new PrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalThis.prisma = db;
}


dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

// enable files upload
app.use(fileUpload({
  createParentPath: true
}));

app.use(express.static('uploads'));

app.use(cors());
app.use(express.json({ limit: "50mb" }));


app.post("/api/login", async (req, res) => {
  // console.log(req.body);
  const { password, email } = req.body;
  // console.log(userData);
  if (!email || !password) return res.status(400).send({ message: "Missing email or password." });

  // try {


  const user = await db.user.findUnique({ where: { email, password } });

  if (!user) return res.status(404).json({ message: "User not found." });

  jwt.sign({ user }, process.env.JWT_SECRET, { expiresIn: "7d" }, (err, token) => {
    if (err) throw err;

    res.status(200).json({ token });

  })

  // } catch (error) {
  //   res.status(500).json({ message: "internal error." });
  // }
}
)


app.post("/api/register", async (req, res) => {
  // console.log(req.body);
  const { name, password, level, studentId, email, gender } = req.body;
  // console.log(userData);
  if (!name) return res.status(400).send({ message: "name is missing!" });

  if (!password) return res.status(400).send({ message: "password is missing!" });

  if (!studentId) return res.status(400).send({ message: "studentId is missing!" });

  if (!email) return res.status(400).send({ message: "email is missing!" });

  if (!level) return res.status(400).send({ message: "level is missing!" });

  // try {

  const existingUser = await db.user.findFirst({
    where: {
      OR: [
        { email },
        { studentId }
      ],
    }
  });

  if (existingUser) {
    res.status(403).json({ message: "Email or Student ID already in use." });
    return;
  }

  const user = await db.user.create({ data: { name, level, studentId, email, password, gender } });

  jwt.sign({ user }, process.env.JWT_SECRET, { expiresIn: "7d" }, (err, token) => {
    if (err) throw err;

    res.status(201).json({ token });

  })

}
)

app.get("/api/active_user", verifyToken, (req, res) => {

  jwt.verify(req.token, process.env.JWT_SECRET, async (err, authData) => {
    if (err) {
      res.sendStatus(403);
    } else {
      const { user } = authData;
      try {
        const activeUser = await db.user.findUnique({
          where: {
            id: user.id
          },
          include: {
            favoriteStores: {
              include: {
                store: true
              }
            }
          }
        })

        if (!activeUser) {
          return res.status(404).json({ message: "User not found" })
        }

        const userFavoriteStores = activeUser.favoriteStores.map(store => ({ ...store.store, id: store.id }));

        const formattedUser = { ...activeUser, favoriteStores: userFavoriteStores }
        // console.log(authData)
        res.status(200).json(formattedUser);
      } catch (e) {
        res.status(500).json({ message: "internal error" })
      }
    }
  })
})


app.get("/api/users", verifyToken, (req, res) => {
  jwt.verify(req.token, process.env.JWT_SECRET, async (err, _) => {
    if (err) {
      res.status(403).json({ message: 'Invalid token' });
    } else {
      const users = await db.user.findMany({
        include: {
          favoriteStores: true
        }
      });
      res.status(200).json(users);
    }
  })
})

app.patch("/api/users/:userId", verifyToken, async (req, res) => {
  const userId = req.params.userId; // Retrieve id=require(params
  const decodedToken = jwt.verify(req.token, process.env.JWT_SECRET);
  const { user } = decodedToken;

  if (user.id !== userId && user.role !== UserRole.ADMIN) {
    res.status(401).json({ message: "unauthorized!" });
  }
  const {
    name,
    email,
    password,
    studentId,
    level,
    gender,
    role
  } = req.body;

  if (isNaN(level)) {
    res.status(400).json({ message: "Level must be a number." });
  }

  let avatar;

  try {

    const existingUser = await db.user.findUnique({
      where: {
        id: userId
      }
    })

    if (!existingUser) {
      res.status(404).json({ message: "user not found" });
    }

    if (req.files?.avatar) {

      if (Array.isArray(req.files?.avatar)) {
        res.status(400).json({ message: "avatar must be a single image" });
      }

      const avatarFile = req.files?.avatar;

      if (avatarFile.mimetype.split('/')[0] !== "image") {
        res.status(406).json({ message: "avatar must be an image" });
      }
      try {
        if (existingUser.avatar) {
          fs.unlinkSync('./uploads' + existingUser.avatar);
        }
      } catch (error) {
        console.error(error);
      }
      //Use the mv() method to place the file in the upload directory (i.e. "uploads")
      avatarFile.mv(`./uploads/users/${userId}/` + avatarFile.name);
      avatar = `/users/${userId}/${avatarFile.name}`.replaceAll(` `, "%20");
      // console.log(avatar);
    }

    const updatedUser = await db.user.update({
      where: { id: userId },
      data: {
        name,
        email,
        password,
        studentId,
        level: parseInt(level),
        gender,
        avatar
      }, include: {
        favoriteStores: true
      }
    })

    res.status(200).json(updatedUser); // Return userId and user data
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "internal error" });
  }
})

app.delete("/api/users/:userId", verifyToken, async (req, res) => {
  try {
    const userId = req.params.userId; // Retrieve id=require(params
    const decodedToken = jwt.verify(req.token, process.env.JWT_SECRET);
    const { user } = decodedToken;

    if (user.id !== userId && user.role !== UserRole.ADMIN) {
      res.status(401).json({ message: "unauthorized!" });
    }

    const deletedUser = await db.user.delete({
      where: { id: userId },
    })

    res.status(204).json(deletedUser); // Return userId and user data
  } catch (error) {
    res.status(403).json({ message: 'Invalid token' });
  }
})


function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];

  if (typeof bearerHeader !== "undefined") {
    const bearer = bearerHeader.split(' ');

    const bearerToken = bearer[1];

    jwt.verify(bearerToken, process.env.JWT_SECRET, (err, _) => {
      if (err) {
        if (err.name === 'JsonWebTokenError') {
          // Handle expired token error
          return res.status(401).json({ message: "Token expired" });
        } else {
          // Handle other JWT errors
          return res.status(403).json({ message: "Invalid Token" });
        }
      }
      req.token = bearerToken;
      next();
    });
  } else {
    res.status(403).json({ message: 'No token provided' });
  }
}


app.get("/api/stores", async (_, res) => {
  try {
    const stores = await db.store.findMany({
      include: {
        users: true
      }
    });
    res.status(200).json(stores);
  } catch (error) {
    res.status(500).json(error);
  }
})

app.post("/api/stores", verifyToken, async (req, res) => {
  const decodedToken = jwt.verify(req.token, process.env.JWT_SECRET);
  const { user } = decodedToken;

  const existingUser = await db.user.findUnique({ where: { id: user.id } });
  if (!existingUser) {
    return res.status(403).json({ message: "You are not authorized to make this request" });
  }

  if (existingUser.role !== UserRole.ADMIN) {
    res.status(401).json({ message: "unauthorized!" });
  }

  const {
    name,
    longitude,
    latitude,
  } = req.body;

  if (!name) {
    res.status(400).json({ message: "name is missing" });
  }

  if (!longitude) {
    res.status(400).json({ message: "longitude is missing" });
  }

  if (!latitude) {
    res.status(400).json({ message: "latitude is missing" });
  }

  try {
    const newStore = await db.store.create({
      data: {
        name,
        latitude,
        longitude
      }
    });
    res.status(201).json(newStore);
  } catch (error) {
    console.log("Error in /api/stores POST route: ", error);
    res.status(500).json({ message: "Server Error" });
  }
})

app.patch("/api/stores/:storeId", verifyToken, async (req, res) => {
  const decodedToken = jwt.verify(req.token, process.env.JWT_SECRET);
  const { user } = decodedToken;

  const existingUser = await db.user.findUnique({ where: { id: user.id } });
  if (!existingUser) {
    return res.status(403).json({ message: "You are not authorized to make this request" });
  }

  if (existingUser.role !== UserRole.ADMIN) {
    res.status(401).json({ message: "unauthorized!" });
  }

  const storeId = req.params.storeId;

  if (!storeId) {
    res.status(400).json({ message: "storeId is missing" });
  }

  const {
    name,
    longitude,
    latitude
  } = req.body;

  if (!name) {
    res.status(400).json({ message: "name is missing" });
  }

  if (!latitude || !longitude) {
    res.status(400).json({ message: "coordinates are missing" });
  }

  try {
    const existingStore = await db.store.findUnique({
      where: {
        id: storeId,

      }
    });
    if (!existingStore) {
      res.status(404).json({ message: "store not found" });
    }

    const store = await db.store.update({
      where: { id: storeId },
      data: {
        name,
        longitude,
        latitude
      },
    });
    res.status(200).json(store);
  } catch (error) {
    console.log("Error in /api/stores/:storeId PATCH route: ", error);
    res.status(500).json({ message: "Server Error" });
  }
})

app.get("/api/favorite_stores", verifyToken, async (req, res) => {
  const decodedToken = jwt.verify(req.token, process.env.JWT_SECRET);
  const { user } = decodedToken;


  const existingUser = await db.user.findUnique({ where: { id: user.id } });
  if (!existingUser || !user) {
    return res.status(403).json({ message: "You are not authorized to make this request" });
  }


  try {
    let favoriteStores;

    if (existingUser.role !== UserRole.ADMIN) {
      favoriteStores = await db.favoriteStore.findMany({
        where: {
          userId: existingUser.id
        }
      });
      return res.status(200).json(favoriteStores);
    }

    favoriteStores = await db.favoriteStore.findMany();
    res.status(200).json(favoriteStores);
  } catch (error) {
    console.log("Error getting store to favorites: ", error);
    res.status(500).json(error);
  }

})

app.post("/api/favorite_stores", verifyToken, async (req, res) => {
  const decodedToken = jwt.verify(req.token, process.env.JWT_SECRET);
  const { user } = decodedToken;

  if (!user) {
    res.status(401).json({ message: "unauthorized!" });
  }

  const {
    userId,
    storeId
  } = req.body;

  if (!userId) {
    res.status(400).json({ message: "userId is missing" });
  }

  if (!storeId) {
    res.status(400).json({ message: "storeId is missing" });
  }

  try {

    // check to see if the user already has this store in their favorite list
    const existingFavorites = await db.favoriteStore.findFirst({
      where: {
        userId,
        storeId
      }
    });

    if (existingFavorites) {
      return res.status(406).json({ message: "This store is already on your favorites list." });
    }

    const newFavorite = await db.favoriteStore.create({
      data: {
        userId,
        storeId
      }
    });
    res.status(201).json(newFavorite);


  } catch (error) {
    console.log("Error adding store to favorites: ", error);
    res.status(500).json(error);
  }

})

app.delete("/api/favorite_stores/:favoriteStoreId", verifyToken, async (req, res) => {
  const favoriteStoreId = req.params.favoriteStoreId;
  const decodedToken = jwt.verify(req.token, process.env.JWT_SECRET);
  const { user } = decodedToken;

  if (!user) {
    res.status(401).json({ message: "unauthorized!" });
  }

  try {
    const foundFavorite = await db.favoriteStore.delete({ where: { id: favoriteStoreId } });

    if (!foundFavorite) {
      return res.status(404).json({ message: "Could not find favorite with given id" });
    }
    res.status(200).json(foundFavorite);
  }
  catch (error) {
    console.log("Error adding store to favorites: ", error);
    res.status(500).json(error);
  }

})

app.get("/", (req, res) => res.send("Express on Vercel"));

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


// module.exports = app;

//app.listen(8080, () => console.log('Server has started on port 8080'))
