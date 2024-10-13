require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const { Schema } = mongoose;
const cors = require('cors');

const PORT = 4000;
const app = express();

app.use(cors());
app.use(express.json());

const mongoURI = process.env.MONGO_URI;
mongoose.connect(mongoURI)
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('MongoDB connection error:', err));

const pinSchema = new Schema({
    password: { type: Buffer, required: true },
    salt: { type: Buffer, required: true },
});

const Pin = mongoose.model('Pin', pinSchema);

async function verifyPassword(inputPassword, storedPassword, salt) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(inputPassword, salt, 310000, 32, 'sha256', (err, derivedKey) => {
            if (err) {
                reject(err);
            }
            resolve(crypto.timingSafeEqual(derivedKey, storedPassword));
        });
    });
}

app.post('/check', async (req, res) => {
    const { value } = req.body;
    try {
        const pin = await Pin.findOne(); 
        if (!pin) {
            return res.status(404).json({ message: 'No stored password found' });
        }
        const isMatch = await verifyPassword(value, pin.password, pin.salt);
        if (isMatch) {
            res.json({ message: 'Password is correct' });
        } else {
            res.status(401).json({ message: 'Password is incorrect' });
        }
    } catch (error) {
        console.error('Error verifying password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

const ordersSchema = new Schema({
    date: {
      type: Date,
      required: true,
    },
    clothes: {
      type: Number,
      required: true,
      min: 0,
    },
    saree: {
      type: Number,
      required: true,
      min: 0,
    },
    status: {
      type: String,
      enum: ['Given', 'Received', 'Paid'],
      required: true,
    },
  }, { timestamps: true });

const Order = mongoose.model('Order', ordersSchema);

app.get('/orders', async (req, res) => {
    try {
      const orders = await Order.find();
      res.json(orders);
    } catch (error) {
      console.error('Error fetching orders:', error);
      res.status(500).json({ message: 'Failed to fetch orders' });
    }
});

app.post('/add-order', async (req, res) => {
    try {
      const order = new Order(req.body);
      await order.save();
      res.status(201).json(order);
    } catch (error) {
      console.error('Error adding order:', error);
      res.status(500).json({ message: 'Failed to add order' });
    }
});

app.put('/update-order/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        const updatedOrder = await Order.findByIdAndUpdate(
            id,
            { status },
            { new: true }
        );

        if (!updatedOrder) {
            return res.status(404).json({ message: 'Order not found' });
        }

        res.json(updatedOrder);
    } catch (error) {
        console.error('Error updating order:', error);
        res.status(500).json({ message: 'Failed to update order' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
