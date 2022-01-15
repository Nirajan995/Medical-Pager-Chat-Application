import crypto from "crypto";
import connect from "getstream";
import { StreamChat } from "stream-chat";
import * as bcrypt from "bcrypt";

const api_key = process.env.STREAM_API_KEY;
const api_secret = process.env.STREAM_API_SECRET;
const app_id = process.env.STREAM_API_KEY;

export const signup = async (req, res) => {
  try {
    const { fullName, password, phoneNumber, username } = req.body;
    const userId = crypto.randomBytes(16).toString("hex");
    const serverClient = connect(api_key, api_secret, app_id);
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = serverClient.createUserToken(userId);
    res
      .status(200)
      .json({ token, fullName, username, hashedPassword, phoneNumber });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error });
  }
};

export const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const serverClient = connect(api_key, api_secret, app_id);
    const client = StreamChat.getInstance(api_key, api_secret);

    const { users } = await client.queryUsers({ name: username });

    if (!users.length)
      return res.status(400).json({ message: "User not found" });

    const success = await bcrypt.compare(password, users[0].hashedPassword);

    const token = await serverClient.createUserToken(users[0].id);

    if (success) {
      return res.status(200).json({
        token,
        fullName: users[0].fullName,
        username,
        userId: users[0].id,
      });
    } else {
      return res.status(500).json({ message: " Incorrect Password" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error });
  }
};
