#pragma once

#include "../common.hpp"
#include "./analyzerWorker.hpp"
#include "./deviceConfig.hpp"

#include <mlpack/core.hpp>
#include <mlpack/methods/kmeans/kmeans.hpp>


#include <time.h>
#include <unistd.h>
#include <semaphore.h>


namespace Whisper {


class AnalyzerWorkerThread;
class DeviceConfig;


struct LearnerConfigParam final {
    // Number of required trainning data
    size_t num_train_data = 2000;

    // value of K for Kmeans.
    size_t val_K = 10;

    // Display the debuging information
    bool verbose = true;

    bool save_result = false;
    string save_result_file = "";

    bool load_result = false;
    string load_result_file = "";

    auto inline display_params() const -> void {
        printf("[Whisper Leaner Configuration]\n");
        printf("Record required for training: %ld, K value for Kmeans: %ld\n", num_train_data, val_K);
        if (save_result) {
            printf("Save training result to: %s\n", save_result_file.c_str());
        }
        if (load_result) {
            printf("Load training result from: %s\n", load_result_file.c_str());
        }
    }

    LearnerConfigParam() = default;
    virtual ~LearnerConfigParam() {}
    LearnerConfigParam & operator=(const LearnerConfigParam &) = delete;
    LearnerConfigParam(const LearnerConfigParam &) = delete;

};


class KMeansLearner final {

    friend class AnalyzerWorkerThread;
    friend class DeviceConfig;

private:

    using feature_t = vector<double_t>;

    // Dataset collected from AnalyzeWorker
    vector<vector<double_t> > train_set;
    
    // Mutual exclution lock for trainSet
    mutable sem_t data_sema;
    void inline acquire_semaphore_data() const {
        sem_wait(&data_sema);
    }
    void inline release_semaphore_data() const {
        sem_post(&data_sema);
    }
    // Mutual exclution for training process (only one AnalyeWorker can start the trainning)
    mutable sem_t learn_sema;
    void inline acquire_semaphore_learn() const {
        sem_wait(&learn_sema);
    }
    void inline release_semaphore_learn() const {
        sem_post(&learn_sema);
    }

    // Clustering centers
    vector<feature_t> train_result;

    shared_ptr<LearnerConfigParam> p_learner_config;

    auto save_result_file() const -> bool {
        if (p_learner_config->verbose) {
            LOGF("Save centers to file: %s.", p_learner_config->save_result_file.c_str());
        }
        assert(p_learner_config->save_result);
        try {
            ofstream fs(p_learner_config->load_result_file);
            if (!fs.good()) {
                throw logic_error("Open target file failed.");
            }
            json _j;

            for (size_t i = 0; i < train_result.size(); i ++) {
                json __j;
                for (size_t j = 0; j < train_result[0].size(); j ++) {
                    __j.push_back(train_result[i][j]);
                }
                _j.push_back(__j);
            }
            fs << _j;
            fs.close();
        } catch (exception & e) {
            WARN(e.what());
            return false;
        }

        if (p_learner_config->verbose) {
            LOGF("Save result to file success.");
        }
        return true;
    }

    auto load_result_file() -> bool {
        if (p_learner_config->verbose) {
            LOGF("Load centers form file: %s.", p_learner_config->load_result_file.c_str());
        }
        assert(p_learner_config->load_result);
        try {
            ifstream fs(p_learner_config->load_result_file);
            if (!fs.good()) {
                throw logic_error("Target load file not exist.");
            }
            json centers;
            fs >> centers;
            fs.close();
            if (centers.size() != p_learner_config->val_K) {
                throw logic_error("Cluster centers number mismatch.");
            }
            for (size_t i = 0; i < centers.size(); i ++) {
                train_result.push_back({});
                for (size_t j = 0; j < centers[0].size(); j ++) {
                    train_result[i].push_back(centers[i][j]);
                }
            }
        } catch (exception & e) {
            WARN(e.what());
            return false;
        }

        if (p_learner_config->verbose) {
            LOGF("Load result from file success.");
        }
        start_learn = true;
        finish_learn = true;
        return true;
    }

public:
    
    // Start the learning process
    volatile bool start_learn = false;
    // Finish the learning process
    volatile bool finish_learn = false;
    
    // Default constructor
    KMeansLearner() {
        sem_init(&data_sema, 0, 1);
        sem_init(&learn_sema, 0, 1);
    }

    // Default deconstructor
    ~KMeansLearner() {}
    KMeansLearner & operator=(const KMeansLearner &) const = delete;
    KMeansLearner(const KMeansLearner &) = delete;

    KMeansLearner(const decltype(p_learner_config) p_c): 
            p_learner_config(p_c) {
        sem_init(&data_sema, 0, 1);
        sem_init(&learn_sema, 0, 1);
    }

    // Add single recored to the training dataset
    void add_train_data(feature_t & ve) {
        train_set.push_back(ve);
    }

    // Add a batch of data to the training dataset
    void add_train_data(vector<feature_t> & vve) {
        train_set.insert(train_set.end(), vve.begin(), vve.end());
    }

    // Start the training process.
    // The training process can be started by only one AnalyzeWorker.
    void start_train() {
        if (p_learner_config == nullptr) {
            FATAL_ERROR("Configuration for learner not found.");
        }

        start_learn = true;
        if(p_learner_config->verbose) {
            if (!p_learner_config->load_result) {
                LOGF("Learner: Start training, %ld records.", train_set.size());
            }
        }

        if (p_learner_config->load_result) {
            if (!load_result_file()) {
                FATAL_ERROR("Learner Load result from file failed.");
            } else {
                return;
            }
        }

        // Transform the std::vector representation to arma::matrix
        size_t x_len = train_set.size();
        size_t y_len = train_set[0].size();
        arma::mat dataset(x_len, y_len, arma::fill::randu);
        for (size_t i = 0; i < x_len; i ++) {
            for (size_t j = 0; j < y_len; j ++) {
                dataset(i, j) = train_set[i][j];
            }
        }
        dataset = dataset.t();

        // Call the mlpack KMeans implementation
        arma::mat centroids;
        arma::Row<size_t> assignments;
        mlpack::kmeans::KMeans<> k;
        k.Cluster(dataset, p_learner_config->val_K, assignments, centroids);
        
        // Transform the arma::matrix to std::vector type
        centroids = centroids.t();
        for (size_t i = 0; i < centroids.n_rows; i ++) {
            vector<double_t> ve;
            for (size_t j = 0; j < centroids.n_cols; j ++) {
                ve.push_back(centroids(i, j));
            }
            train_result.push_back(ve);
        }
        finish_learn = true;

        if (p_learner_config->save_result) {
            if (!save_result_file()) {
                FATAL_ERROR("Learner save result to file failed.");
            }
        }

        if(p_learner_config->verbose) {
            LOGF("Learner: Finsih training");
        }
    }

    // Training data is enough or not
    auto inline reach_learn() const -> bool {
        if (p_learner_config == nullptr) {
            FATAL_ERROR("Configuration for learner not found.");
        }
        if (p_learner_config->load_result) {
            return true;
        }
        return train_set.size() > p_learner_config->num_train_data;
    }


    // Getter of clustering center
    auto inline get_K() const -> size_t {
        return p_learner_config->val_K;
    }


    auto configure_via_json(const json & jin) -> bool {
        if (p_learner_config != nullptr) {
            WARN("Learner configuration overleap.");
        }
        p_learner_config = make_shared<LearnerConfigParam>();
        if (p_learner_config == nullptr) {
            WARNF("learner configuration: bad allocation.");
            return false;
        }

        try {
            if (jin.count("val_K")) {
                p_learner_config->val_K = 
                    static_cast<decltype(p_learner_config->val_K)>(jin["val_K"]);
            }
    
            if (jin.count("num_train_data")) {
                p_learner_config->num_train_data = 
                    static_cast<decltype(p_learner_config->num_train_data)>(jin["num_train_data"]);
            }

            if (jin.count("save_result")) {
                p_learner_config->save_result = 
                    static_cast<decltype(p_learner_config->save_result)>(jin["save_result"]);
                if (jin.count("save_result_file")) {
                    p_learner_config->save_result_file = 
                        static_cast<decltype(p_learner_config->save_result_file)>(jin["save_result_file"]);
                }
            }
            if (jin.count("load_result")) {
                p_learner_config->load_result = 
                    static_cast<decltype(p_learner_config->load_result)>(jin["load_result"]);
                if (jin.count("load_result_file")) {
                    p_learner_config->load_result_file = 
                        static_cast<decltype(p_learner_config->load_result_file)>(jin["load_result_file"]);
                }
            }

            if (jin.count("verbose")) {
                p_learner_config->verbose = 
                    static_cast<decltype(p_learner_config->verbose)>(jin["verbose"]);
            }

            if (p_learner_config->load_result && p_learner_config->save_result) {
                throw logic_error("Can not save tarining result while load the result.");
            }
        } catch (exception & e) {
            WARN(e.what());
            return false;
        }

        return true;
    }
};


}
