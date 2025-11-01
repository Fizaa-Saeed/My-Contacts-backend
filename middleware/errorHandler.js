
//2nd middleware/errorHandler.js (CORRECTED CODE)

// const { constants} =require("../constants");

// const errorHandler = (err, req,res, next) =>{
//     const statusCode = res.statusCode
//         ? res.statusCode : 500

//     switch (statusCode) {
        
//         case constants.VALIDATION_ERROR:
//             res.json({title: "Validation Failed", message:err.message, stackTrace: err.stack});
//             break; // <-- ADDED
            
//         case constants.UNAUTHORIZED:
//             res.json({title: "Unauthorized", message: err.message, stackTrace: err.stack});
//             break; // <-- ADDED
            
//         case constants.NOT_FOUND:
//             res.json({title: "Not Found", message:err.message, stackTrace: err.stack});
//             break; // <-- ADDED
            
//         case constants.FORBIDDEN:
//             res.json({title: "Forbidden", message:err.message, stackTrace: err.stack});
//             break; // <-- ADDED
            
//         case constants.SERVER_ERROR:
//             res.json({title: "Server Error", message: err.message, stackTrace: err.stack});
//             break; // <-- ADDED
            
//         default:
//             console.log("No Error !");
//             break;
//     }
// };
// module.exports = errorHandler;
//first code
// const { constants} =require("../constants");

// const errorHandler = (err, req, res, next) =>{
// const statusCode = res.statusCode ? res.statusCode : 500

// switch (statusCode) {
//     case constants.VALIDATION_ERROR:
//         res.json({title: "Validation Failed", message: err.message, stackTrace: err.stack});
//         break;
// case constants.UNAUTHORIZED:
// res.json({title: "Unauthorized", message: err.message, stackTrace: err.stack});

// case constants.NOT_FOUND:
// res.json({title: "Not Found", message: err.message, stackTrace: err.stack});

// case constants.FORBIDDEN:
// res.json({title: "Forbidden", message: err.message, stackTrace: err.stack});
// case constants.SERVER_ERROR:
// res.json({title: "Server Error", message: err.message, stackTrace: err.stack});


//     default:
//         console.log("No Error !");
//         break;
// }

// };

// module.exports = errorHandler;

// middleware/errorHandler.js
const { constants } = require("../constants");

const errorHandler = (err, req, res, next) => {
  const statusCode = res.statusCode ? res.statusCode : 500;

  switch (statusCode) {
    case constants.VALIDATION_ERROR:
      res.json({ title: "Validation Failed", message: err.message, stackTrace: err.stack });
      break;
    case constants.UNAUTHORIZED:
      res.json({ title: "Unauthorized", message: err.message, stackTrace: err.stack });
      break;
    case constants.NOT_FOUND:
      res.json({ title: "Not Found", message: err.message, stackTrace: err.stack });
      break;
    case constants.FORBIDDEN:
      res.json({ title: "Forbidden", message: err.message, stackTrace: err.stack });
      break;
    case constants.SERVER_ERROR:
      res.json({ title: "Server Error", message: err.message, stackTrace: err.stack });
      break;
    default:
      res.json({ title: "Error", message: err.message, stackTrace: err.stack });
      break;
  }
};

module.exports = errorHandler;
