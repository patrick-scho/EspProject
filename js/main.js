console.log("Loading browser sdk");

const sdk = matrixcs;

const myUserId = "@psch:matrix.org";
const myAccessToken = "syt_cHNjaG8_lPLjYLphLXBJVgTBbsEn_1tVbV1";
const matrixClient = sdk.createClient({
    baseUrl: "https://matrix.org",
    accessToken: myAccessToken,
    userId: myUserId,
});

matrixClient.getJoinedRooms().then((joined_rooms) => {
  console.log("Joined Rooms: ", joined_rooms);
});

const testRoomId = "!koVStwyiiKcBVbXZYz:matrix.org";

const content = {
    "body": "Hello World",
    "msgtype": "m.text"
};

matrixClient.sendEvent(testRoomId, "m.room.message", content, "").then((res) => {
   // message sent successfully
}).catch((err) => {
    console.log(err);
});